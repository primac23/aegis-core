#!/usr/bin/env bash
# Guardian refuses to sign when independent RPCs disagree (the Kelp RPC-poisoning scenario).
set -uo pipefail
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
C="$ROOT/contracts"; E="$ROOT/engine"
RA=http://127.0.0.1:8545    # sursă onest 1
RA2=http://127.0.0.1:8547   # sursă onest 2 (clonă)
RP=http://127.0.0.1:8548    # RPC otrăvit (fork divergent)
RB=http://127.0.0.1:8546    # destinație
DEPLOYER=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ALICE=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
K=3; ATT=/tmp/aegis_poison; LOGS=/tmp/aegis_poison_logs
GRN='\033[1;32m'; RED='\033[1;31m'; YEL='\033[1;33m'; CYN='\033[1;36m'; NC='\033[0m'; D=()

say(){ echo -e "  $*"; }; phase(){ echo -e "\n${CYN}━━━ $1 ━━━${NC}"; }
pkill -f 'anvil --port 854[5678]' 2>/dev/null; pkill -f 'engine guardian' 2>/dev/null; sleep 1
rm -rf "$ATT" "$LOGS"; mkdir -p "$LOGS"
# Trei noduri "sursă" pornite identic (mnemonic implicit, aceleași tranzacții de deploy → aceleași hash-uri),
# plus destinația.
anvil --port 8545 --chain-id 1111 --silent & PA=$!
anvil --port 8547 --chain-id 1111 --silent & PA2=$!
anvil --port 8548 --chain-id 1111 --silent & PP=$!
anvil --port 8546 --chain-id 2222 --silent & PB=$!
trap 'kill "${D[@]}" $PA $PA2 $PP $PB 2>/dev/null' EXIT
sleep 2
(cd "$E" && cargo build --release -q) || exit 1
BIN="$E/target/release/engine"
cd "$C"; forge build >/dev/null 2>&1

# Deploy identic pe toate cele 3 surse (ca să înceapă cu aceeași stare), destinația separat.
for RPC in $RA $RA2 $RP; do
  forge script script/DeployCrossChain.s.sol:DeployChainA --rpc-url $RPC --broadcast --non-interactive >/dev/null 2>&1
done
SRC=0x5FbDB2315678afecb367f032d93F642f64180aa3
BRG=$(forge script script/DeployCrossChain.s.sol:DeployChainB --rpc-url $RB --broadcast --non-interactive 2>&1 | awk '/deployed at/{print $NF}')
say "Sursă (3 RPC-uri): $SRC | Firewall: $BRG"

# Un singur guardian, dar care citește din 3 RPC-uri, cvorum 3.
SRC_RPCS="$RA,$RA2,$RP" DST_RPC=$RB SRC_CONTRACT=$SRC BRIDGE=$BRG \
  GUARDIAN_KEY=0x0000000000000000000000000000000000000000000000000000000000001111 \
  K=$K SET_ID=1 RPC_QUORUM=3 ATTEST_DIR=$ATT POLL_MS=250 \
  "$BIN" guardian > "$LOGS/guardian.log" 2>&1 &
D+=($!); sleep 2
grep -h online "$LOGS/guardian.log" | sed 's/^/  /'

mine(){ for _ in $(seq "$1"); do for RPC in $RA $RA2 $RP; do cast rpc evm_mine --rpc-url $RPC >/dev/null; done; done; }

phase "A. Toate 3 RPC-urile de acord → guardianul semnează"
for RPC in $RA $RA2 $RP; do
  cast send --async "$SRC" "deposit(address,uint256)" "$ALICE" 10000000000000000000 --rpc-url $RPC --private-key $DEPLOYER >/dev/null
done
mine $K; sleep 3
if grep -q 'SIGNED' "$LOGS/guardian.log"; then say "${GRN}✔ SIGNED (consens 3/3)${NC}"; else say "${RED}✘ nu a semnat${NC}"; fi

phase "B. RPC otrăvit — al 3-lea nod pe un fork divergent"
# Avansăm doar RPC-ul otrăvit cu un bloc în plus, apoi facem un depozit pe toate:
# la înălțimea depozitului, nodul otrăvit va avea alt block hash decât celelalte două.
cast rpc evm_mine --rpc-url $RP >/dev/null
for RPC in $RA $RA2 $RP; do
  cast send --async "$SRC" "deposit(address,uint256)" "$ALICE" 25000000000000000000 --rpc-url $RPC --private-key $DEPLOYER >/dev/null
done
mine $K; sleep 4
if grep -q 'RPC-POISON' "$LOGS/guardian.log"; then
  say "${GRN}✔ Guardianul a detectat divergența RPC și a REFUZAT să semneze${NC}"
  grep 'RPC-POISON' "$LOGS/guardian.log" | tail -1 | sed 's/^/    /'
else
  say "${RED}✘ Divergența NU a fost detectată${NC}"
fi

phase "Jurnal guardian"
grep -E 'OBSERVED|STATUS|SIGNED|RPC-POISON|REFUSED' "$LOGS/guardian.log" | sed 's/^/  /'
