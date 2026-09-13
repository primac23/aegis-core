#!/usr/bin/env bash
set -euo pipefail

# Curățare procese reziduale
pkill -f "anvil --port 8545" || true
pkill -f "anvil --port 8546" || true

echo "[INIT] Pornire Chain A (Sursa) pe portul 8545 (Chain ID: 1111)..."
anvil --port 8545 --chain-id 1111 --silent &
PID_A=$!

echo "[INIT] Pornire Chain B (Destinatie) pe portul 8546 (Chain ID: 2222)..."
anvil --port 8546 --chain-id 2222 --silent &
PID_B=$!

trap "echo '[EXIT] Oprire noduri Anvil...'; kill $PID_A $PID_B || true" EXIT

sleep 2

echo "[OK] Chain A asculta pe http://127.0.0.1:8545"
echo "[OK] Chain B asculta pe http://127.0.0.1:8546"

# Așteaptă semnal de oprire
wait
