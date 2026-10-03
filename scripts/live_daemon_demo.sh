#!/usr/bin/env bash
# AEGIS end-to-end: two independent Rust guardian daemons (2-of-3) enforce the finality policy on live Anvil chains.
set -uo pipefail
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
C="$ROOT/contracts"; E="$ROOT/engine"
RA=http://127.0.0.1:8545; RB=http://127.0.0.1:8546
DEPLOYER=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ALICE=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
K=3; ATT=/tmp/aegis_attest; LOGS=/tmp/aegis_guardians
GRN='\033[1;32m'; RED='\033[1;31m'; YEL='\033[1;33m'; CYN='\033[1;36m'; NC='\033[0m'
SUMMARY=(); FAILS=0; DAEMONS=()

say()    { echo -e "  $*"; }
phase()  { echo -e "\n${CYN}━━━ $1 ━━━${NC}"; }
record() { SUMMARY+=("$1|$2|$3"); }
mine()   { for _ in $(seq "$1"); do cast rpc evm_mine --rpc-url $RA >/dev/null; done; }
snap()   { cast rpc evm_snapshot --rpc-url $RA | tr -d '"'; }
reorg()  { cast rpc evm_revert "$1" --rpc-url $RA >/dev/null
           cast rpc anvil_dropAllTransactions --rpc-url $RA >/dev/null 2>&1; mine "$2"; }
expect() { if [[ "$2" == "$3" ]]; then say "${GRN}✔ $3${NC}"; record "$1" "$3" "OK"
           else say "${RED}✘ așteptat $2, obținut $3${NC}"; record "$1" "$3" "NEAȘTEPTAT"; FAILS=$((FAILS+1)); fi; }

pkill -f 'anvil --port 854[56]' 2>/dev/null; pkill -f 'engine guardian' 2>/dev/null; sleep 1
rm -rf "$ATT" "$LOGS"; mkdir -p "$LOGS"
anvil --port 8545 --chain-id 1111 --silent & PA=$!
anvil --port 8546 --chain-id 2222 --silent & PB=$!
cleanup() { kill "${DAEMONS[@]}" "$PA" "$PB" 2>/dev/null; }
trap cleanup EXIT
sleep 2

(cd "$E" && cargo build --release -q) || { echo "cargo build eșuat"; exit 1; }
BIN="$E/target/release/engine"
cd "$C" || exit 1
forge build >/dev/null 2>&1
SRC=$(forge script script/DeployCrossChain.s.sol:DeployChainA --rpc-url $RA --broadcast --non-interactive 2>&1 | awk '/deployed at/{print $NF}')
BRG=$(forge script script/DeployCrossChain.s.sol:DeployChainB --rpc-url $RB --broadcast --non-interactive 2>&1 | awk '/deployed at/{print $NF}')
[[ -n "$SRC" && -n "$BRG" ]] || { echo -e "${RED}Deploy eșuat${NC}"; exit 1; }

declare -A ERR
for e in AttestationMissing AttestationInvalid AttestationExpired AttestationNotYetValid MessageAlreadyReleased \
         QuorumNotReached DuplicateSigner InvalidSigner InvalidMessage InvalidGuardianSet; do
  ERR[$e]=$(cast sig "$e()")
done

start_guardian() {  # $1 = index (1..3)
  local key; key=$(printf '0x%064x' $((0x1111 * $1)))
  SRC_RPC=$RA DST_RPC=$RB SRC_CONTRACT=$SRC BRIDGE=$BRG GUARDIAN_KEY=$key K=$K SET_ID=1 \
    ATTEST_DIR=$ATT POLL_MS=250 "$BIN" guardian > "$LOGS/guardian$1.log" 2>&1 &
  DAEMONS+=($!)
}

deposit() {  # $1 = ETH -> TX BN MSG MH
  local wei n; wei=$(cast to-wei "$1")
  n=$(cast call "$SRC" 'nonce()(uint256)' --rpc-url $RA | awk '{print $1}')
  TX=$(cast send --async "$SRC" "deposit(address,uint256)" "$ALICE" "$wei" --rpc-url $RA --private-key $DEPLOYER)
  BN=$(cast receipt "$TX" blockNumber --rpc-url $RA)
  MSG=$(cast abi-encode "f(address,uint256,uint256,uint256,address)" "$ALICE" "$wei" "$n" 1111 "$SRC")
  MH=$(cast keccak "$MSG")
  say "Chain A: deposit $1 ETH → Alice | nonce $n | bloc $BN | msg ${MH:0:12}…"
}

wait_ready() {  # $1 = msg hash, $2 = timeout seconds
  local i
  for i in $(seq 1 $((2 * $2))); do
    ATTEST_DIR=$ATT THRESHOLD=2 "$BIN" aggregate >/dev/null 2>&1
    [[ -f "$ATT/$1/ready.att" ]] && return 0
    sleep 0.5
  done
  return 1
}

try_release() {  # $1 = msg, $2 = attestation
  local out rc
  out=$(cast call "$BRG" "release(bytes,bytes)" "$1" "$2" --rpc-url $RB 2>&1); rc=$?
  if (( rc == 0 )); then
    cast send "$BRG" "release(bytes,bytes)" "$1" "$2" --rpc-url $RB --private-key $DEPLOYER >/dev/null 2>&1 \
      && echo RELEASED || echo SEND_FAILED
    return
  fi
  for e in "${!ERR[@]}"; do grep -qiE "$e|${ERR[$e]#0x}" <<<"$out" && { echo "$e"; return; }; done
  echo REVERT_UNKNOWN
}

phase "Pornire guardieni (2 procese Rust independente, prag 2-of-3)"
start_guardian 1; start_guardian 2; sleep 2
grep -h 'online' "$LOGS"/guardian*.log | sed 's/^/  /'

phase "A. Transfer legitim — guardienii semnează după K=$K confirmări"
deposit 10; mine $K
if wait_ready "$MH" 20; then
  say "Agregator: cvorum 2-of-3 atins, atestare construită din semnăturile daemonilor"
  MSG_A=$(cat "$ATT/$MH/message.hex"); ATT_A=$(cat "$ATT/$MH/ready.att")
  [[ "$MSG_A" == "$MSG" ]] && say "Payload din eveniment = payload așteptat ✔"
  expect "A. legitim (daemoni)" RELEASED "$(try_release "$MSG_A" "$ATT_A")"
else
  record "A. legitim (daemoni)" NO_QUORUM NEAȘTEPTAT; FAILS=$((FAILS+1)); MSG_A=$MSG; ATT_A=0x
fi

phase "B. Replay al aceleiași atestări"
expect "B. replay" MessageAlreadyReleased "$(try_release "$MSG_A" "$ATT_A")"

phase "C. Reorg pe sursă înainte de finalitate"
S=$(snap); deposit 25; MH_C=$MH; MSG_C=$MSG
sleep 1.5
say "Guardieni: $(grep -h "STATUS] msg ${MH_C:0:12}" "$LOGS"/guardian1.log | tail -1 | sed 's/.*-> //')"
reorg "$S" $((K + 1)); sleep 2
REFUSED=$(grep -l "REFUSED\] msg ${MH_C:0:12}" "$LOGS"/guardian*.log 2>/dev/null | wc -l)
say "${YEL}REORG${NC}: depozitul a dispărut din lanțul canonic | guardieni care au refuzat: $REFUSED/2"
ATTEST_DIR=$ATT THRESHOLD=2 "$BIN" aggregate >/dev/null 2>&1
[[ -f "$ATT/$MH_C/ready.att" ]] && say "${RED}atestare găsită — NEAȘTEPTAT${NC}" || say "Nicio atestare pentru mesajul orfan"
if (( REFUSED == 2 )); then expect "C. reorg (daemoni)" AttestationMissing "$(try_release "$MSG_C" 0x)"
else record "C. reorg (daemoni)" "REFUSED=$REFUSED" NEAȘTEPTAT; FAILS=$((FAILS+1)); fi

phase "D. Transfer legitim identic (10 ETH → Alice din nou)"
deposit 10; mine $K
if wait_ready "$MH" 20; then
  expect "D. duplicat legitim" RELEASED "$(try_release "$(cat "$ATT/$MH/message.hex")" "$(cat "$ATT/$MH/ready.att")")"
else record "D. duplicat legitim" NO_QUORUM NEAȘTEPTAT; FAILS=$((FAILS+1)); fi

phase "E. Un guardian oprit — 1 din 3 online"
kill "${DAEMONS[1]}" 2>/dev/null; sleep 1
deposit 5; mine $K
if wait_ready "$MH" 6; then record "E. 1/3 guardieni online" RELEASABLE NEAȘTEPTAT; FAILS=$((FAILS+1))
else
  say "Agregator: o singură semnătură, cvorum imposibil → fail-closed"
  expect "E. 1/3 guardieni online" AttestationMissing "$(try_release "$MSG" 0x)"
fi

phase "Jurnal guardian 1"
grep -E 'OBSERVED|STATUS|SIGNED|REFUSED|DONE' "$LOGS/guardian1.log" | sed 's/^/  /'

echo -e "\n${CYN}━━━ REZUMAT ━━━${NC}"
printf '  %-26s %-24s %s\n' SCENARIU REZULTAT VERDICT
for l in "${SUMMARY[@]}"; do IFS='|' read -r a b c <<<"$l"; printf '  %-26s %-24s %s\n' "$a" "$b" "$c"; done
exit "$FAILS"
