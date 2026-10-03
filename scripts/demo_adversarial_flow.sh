#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "    AEGIS CROSS-CHAIN ADVERSARIAL VALIDATION HARNESS      "
echo "=========================================================="

fuser -k 8545/tcp 8546/tcp 2>/dev/null || true
pkill -9 -f anvil 2>/dev/null || true
sleep 1

anvil --port 8545 --chain-id 1111 --silent &
PID_A=$!
anvil --port 8546 --chain-id 2222 --silent &
PID_B=$!

trap "kill -9 $PID_A $PID_B 2>/dev/null || true" EXIT
sleep 2

cd "$(dirname "$(readlink -f "$0")")/../contracts"

echo "[1/4] Deploy SourceDepositBox pe Chain A (port 8545)..."
OUT_A=$(forge script script/DeployCrossChain.s.sol:DeployChainA --rpc-url http://127.0.0.1:8545 --broadcast --non-interactive)
ADDR_A=$(echo "$OUT_A" | grep "SourceDepositBox deployed at:" | awk '{print $NF}')
echo "       -> Adresa Sursa: $ADDR_A"

echo "[2/4] Deploy IFirewallGatedBridge pe Chain B (port 8546)..."
OUT_B=$(forge script script/DeployCrossChain.s.sol:DeployChainB --rpc-url http://127.0.0.1:8546 --broadcast --non-interactive)
ADDR_B=$(echo "$OUT_B" | grep "IFirewallGatedBridge deployed at:" | awk '{print $NF}')
echo "       -> Adresa Firewall: $ADDR_B"

echo "[3/4] Initiere depunere pe Chain A (10 ETH catre Alice)..."
ALICE="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
cast send "$ADDR_A" "deposit(address,uint256)" "$ALICE" 10000000000000000000 \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 >/dev/null
echo "       -> Eveniment Deposit inregistrat pe Chain A."

echo "[4/4] Test Adversarial: Tentativa de release fraudulos pe Chain B (fara atestare)..."
PAYLOAD=$(cast abi-encode "transfer(address,uint256)" "$ALICE" 10000000000000000000)

if cast send "$ADDR_B" "release(bytes,bytes)" "$PAYLOAD" "0x" \
  --rpc-url http://127.0.0.1:8546 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 2>/dev/null; then
    echo "[EROARE CRITICA]: Tranzactia a trecut fara atestare!"
    exit 1
else
    echo "       -> [VERIFICAT] Tranzactia a fost respinsa cu REVERT de EVM (Fail-Closed activ)."
fi

echo "=========================================================="
echo "       AEGIS HARNESS: TOATE VERIFICARILE AU TRECUT        "
echo "=========================================================="
