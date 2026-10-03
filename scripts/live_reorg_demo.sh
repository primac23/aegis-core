#!/usr/bin/env bash
# AEGIS live dual-chain demo: legit, replay, reorg (naive vs finality-aware guardians), duplicate payload
set -uo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
cd "$(dirname "$(readlink -f "$0")")/../contracts" || exit 1

RA=http://127.0.0.1:8545; RB=http://127.0.0.1:8546
DEPLOYER=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ALICE=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
GK=(0x0000000000000000000000000000000000000000000000000000000000001111
    0x0000000000000000000000000000000000000000000000000000000000002222)
K=3; SET_ID=1
GRN='\033[1;32m'; RED='\033[1;31m'; YEL='\033[1;33m'; CYN='\033[1;36m'; NC='\033[0m'
SUMMARY=()

say()    { echo -e "  $*"; }
phase()  { echo -e "\n${CYN}━━━ $1 ━━━${NC}"; }
record() { SUMMARY+=("$1|$2|$3"); }
mine()   { for _ in $(seq "$1"); do cast rpc evm_mine --rpc-url $RA >/dev/null; done; }
reorg()  { cast rpc evm_revert "$1" --rpc-url $RA >/dev/null
           cast rpc anvil_dropAllTransactions --rpc-url $RA >/dev/null 2>&1; mine "$2"; }
snap()   { cast rpc evm_snapshot --rpc-url $RA | tr -d '"'; }

# ---------- chains + deploy ----------
pkill -f 'anvil --port 854[56]' 2>/dev/null; sleep 1
anvil --port 8545 --chain-id 1111 --silent & PA=$!
anvil --port 8546 --chain-id 2222 --silent & PB=$!
trap 'kill $PA $PB 2>/dev/null' EXIT
sleep 2
forge clean >/dev/null 2>&1; forge build >/dev/null 2>&1
SRC=$(forge script script/DeployCrossChain.s.sol:DeployChainA --rpc-url $RA --broadcast --non-interactive 2>&1 | awk '/deployed at/{print $NF}')
BRG=$(forge script script/DeployCrossChain.s.sol:DeployChainB --rpc-url $RB --broadcast --non-interactive 2>&1 | awk '/deployed at/{print $NF}')
[[ -n "$SRC" && -n "$BRG" ]] || { echo -e "${RED}Deploy eșuat${NC}"; exit 1; }
echo -e "${CYN}Chain A (1111) SourceDepositBox: $SRC\nChain B (2222) Firewall:         $BRG${NC}"

declare -A ERR
for e in AttestationMissing AttestationInvalid AttestationExpired AttestationNotYetValid MessageAlreadyReleased \
         QuorumNotReached DuplicateSigner InvalidSigner InvalidMessage InvalidGuardianSet; do
  ERR[$e]=$(cast sig "$e()")
done

# ---------- primitives ----------
deposit() {  # $1 = ETH -> TX BN ROOT MSG MH
  local wei; wei=$(cast to-wei "$1")
  N=$(cast call "$SRC" 'nonce()(uint256)' --rpc-url $RA | awk '{print $1}')
  TX=$(cast send --async "$SRC" "deposit(address,uint256)" "$ALICE" "$wei" --rpc-url $RA --private-key $DEPLOYER)
  BN=$(cast receipt "$TX" blockNumber --rpc-url $RA)
  ROOT=$(cast block "$BN" -f stateRoot --rpc-url $RA)
  MSG=$(cast abi-encode "f(address,uint256,uint256,uint256,address)" "$ALICE" "$wei" "$N" 1111 "$SRC")
  MH=$(cast keccak "$MSG")
  say "Chain A: deposit $1 ETH → Alice | tx ${TX:0:12}… | bloc $BN | root ${ROOT:0:14}…"
}

canonical_status() {  # $1=tx $2=block -> FINAL | PENDING(x/K) | ORPHANED
  local r h_r h_c head
  r=$(cast rpc eth_getTransactionReceipt "$1" --rpc-url $RA 2>/dev/null)
  [[ -z "$r" || "$r" == "null" ]] && { echo ORPHANED; return; }
  h_r=$(grep -oE '"blockHash": *"0x[0-9a-f]{64}"' <<<"$r" | grep -oE '0x[0-9a-f]{64}' | head -1)
  h_c=$(cast block "$2" -f hash --rpc-url $RA 2>/dev/null)
  [[ "$h_r" == "$h_c" ]] || { echo ORPHANED; return; }
  head=$(cast block-number --rpc-url $RA)
  (( head - $2 >= K )) && echo FINAL || echo "PENDING($((head - $2))/$K)"
}

attest() {  # 2-of-3 EIP-712 signatures over (MH, ROOT, BN) -> ATT
  local now va vu digest a sig entries=() tup="" v r s
  now=$(date +%s); va=$((now - 5)); vu=$((now + 90))
  digest=$(cast call "$BRG" "hashTypedAttestation(bytes32,bytes32,uint256,uint256,uint256,uint256)(bytes32)" \
           "$MH" "$ROOT" $va $vu "$BN" $SET_ID --rpc-url $RB)
  for k in "${GK[@]}"; do
    a=$(cast wallet address --private-key "$k" | tr 'A-F' 'a-f')
    sig=$(cast wallet sign --no-hash --private-key "$k" "$digest")
    entries+=("$a|$((16#${sig:130:2}))|0x${sig:2:64}|0x${sig:66:64}")
  done
  while IFS='|' read -r _ v r s; do tup+="($v,$r,$s),"; done < <(printf '%s\n' "${entries[@]}" | sort)
  ATT=$(cast abi-encode "f((bytes32,bytes32,uint256,uint256,uint256,uint256,(uint8,bytes32,bytes32)[]))" \
        "($MH,$ROOT,$va,$vu,$BN,$SET_ID,[${tup%,}])")
  say "Guardieni: 2-of-3 semnături pe (msg ${MH:0:12}…, root ${ROOT:0:14}…, bloc $BN)"
}

try_release() {  # $1=msg $2=att -> RELEASED | <ErrorName>
  local out rc
  out=$(cast call "$BRG" "release(bytes,bytes)" "$1" "$2" --rpc-url $RB 2>&1); rc=$?
  if (( rc == 0 )); then
    cast send "$BRG" "release(bytes,bytes)" "$1" "$2" --rpc-url $RB --private-key $DEPLOYER >/dev/null 2>&1 \
      && echo RELEASED || echo SEND_FAILED
    return
  fi
  for e in "${!ERR[@]}"; do grep -qiE "$e|${ERR[$e]#0x}" <<<"$out" && { echo "$e"; return; }; done
  echo "REVERT_UNKNOWN"
}

expect() {  # $1=scenariu $2=așteptat $3=obținut
  if [[ "$2" == "$3" ]]; then say "${GRN}✔ $3${NC}"; record "$1" "$3" "OK"
  else say "${RED}✘ așteptat $2, obținut $3${NC}"; record "$1" "$3" "NEAȘTEPTAT"; fi
}

# ---------- A ----------
phase "A. Transfer legitim (K=$K confirmări → atestare → release)"
deposit 10; mine $K
say "Daemon guardian: status sursă = $(canonical_status "$TX" "$BN")"
[[ $(canonical_status "$TX" "$BN") == FINAL ]] || { echo -e "${RED}A: sursa nu e FINAL, abort${NC}"; exit 1; }
attest; MSG_A=$MSG; ATT_A=$ATT; MH_A=$MH
expect "A. legitim" RELEASED "$(try_release "$MSG_A" "$ATT_A")"
say "released[msg] pe Chain B = $(cast call "$BRG" 'released(bytes32)(bool)' "$MH_A" --rpc-url $RB)"

# ---------- B ----------
phase "B. Replay: aceeași atestare trimisă din nou"
expect "B. replay" MessageAlreadyReleased "$(try_release "$MSG_A" "$ATT_A")"

# ---------- C ----------
phase "C. Reorg cu guardieni NAIVI (semnează la 0 confirmări)"
S=$(snap); deposit 25; TX_C=$TX; BN_C=$BN; ROOT_C=$ROOT
attest; MSG_C=$MSG; ATT_C=$ATT
reorg "$S" 1
say "${YEL}REORG Chain A:${NC} bloc $BN_C root ${ROOT_C:0:14}… → $(cast block "$BN_C" -f stateRoot --rpc-url $RA | cut -c1-16)… | depozit: $(canonical_status "$TX_C" "$BN_C")"
RES=$(try_release "$MSG_C" "$ATT_C")
if [[ $RES == RELEASED ]]; then
  say "${RED}⚠ GAP: Chain B a eliberat 25 ETH pentru un depozit care NU mai există pe sursă${NC}"
  record "C. reorg, guardieni naivi" RELEASED "GAP CONFIRMAT"
else say "Blocat: $RES"; record "C. reorg, guardieni naivi" "$RES" "blocat"; fi

# ---------- D ----------
phase "D. Reorg cu guardieni FINALITY-AWARE (K=$K + verificare canonică)"
S=$(snap); deposit 7; TX_D=$TX; BN_D=$BN; MSG_D=$MSG
say "Daemon guardian: status = $(canonical_status "$TX_D" "$BN_D") → așteaptă finalitatea"
reorg "$S" $((K + 1))
ST=$(canonical_status "$TX_D" "$BN_D"); say "${YEL}REORG Chain A${NC} în fereastra de așteptare → status = $ST"
if [[ $ST == FINAL ]]; then attest; ATT_D=$ATT; else say "Daemon guardian: ${GRN}REFUZĂ atestarea${NC}"; ATT_D=0x; fi
expect "D. reorg, finality-aware" AttestationMissing "$(try_release "$MSG_D" "$ATT_D")"

# ---------- E ----------
phase "E. Al doilea transfer legitim identic (10 ETH → Alice, din nou)"
deposit 10; mine $K
say "Daemon guardian: status sursă = $(canonical_status "$TX" "$BN")"
[[ $(canonical_status "$TX" "$BN") == FINAL ]] || { echo -e "${RED}E: sursa nu e FINAL, abort${NC}"; exit 1; }
attest
expect "E. duplicat legitim (nonce)" RELEASED "$(try_release "$MSG" "$ATT")"

# ---------- summary ----------
echo -e "\n${CYN}━━━ REZUMAT ━━━${NC}"
printf '  %-28s %-24s %s\n' SCENARIU REZULTAT VERDICT
for l in "${SUMMARY[@]}"; do IFS='|' read -r a b c <<<"$l"; printf '  %-28s %-24s %s\n' "$a" "$b" "$c"; done
