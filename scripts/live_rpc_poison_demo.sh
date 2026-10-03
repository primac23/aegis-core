#!/usr/bin/env bash
# One honest source chain; the guardian reads it through 3 RPC URLs. A poison proxy
# rewrites one endpoint's block hash, reproducing the KelpDAO RPC-poisoning class.
set -uo pipefail
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
C="$ROOT/contracts"; E="$ROOT/engine"
RA=http://127.0.0.1:8545      # lanț sursă (onest)
RB=http://127.0.0.1:8546      # destinație
PROXY=http://127.0.0.1:8549   # proxy otrăvitor spre RA
DEPLOYER=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ALICE=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
K=3; ATT=/tmp/aegis_poison; LOGS=/tmp/aegis_poison_logs
GRN='\033[1;32m'; RED='\033[1;31m'; YEL='\033[1;33m'; CYN='\033[1;36m'; NC='\033[0m'; D=()
say(){ echo -e "  $*"; }; phase(){ echo -e "\n${CYN}━━━ $1 ━━━${NC}"; }

pkill -f 'anvil --port 854[56]' 2>/dev/null; pkill -f 'engine guardian' 2>/dev/null
pkill -f 'aegis_poison_proxy' 2>/dev/null; sleep 1
rm -rf "$ATT" "$LOGS"; mkdir -p "$LOGS"
anvil --port 8545 --chain-id 1111 --silent & PA=$!
anvil --port 8546 --chain-id 2222 --silent & PB=$!
trap 'kill "${D[@]}" $PA $PB $PROXY_PID 2>/dev/null; rm -f /tmp/aegis_poison_proxy.py' EXIT
sleep 2

# Proxy otrăvitor: forward transparent spre RA, dar pentru eth_getBlockByNumber
# întoarce un hash fals DOAR când fișierul de flag există. Altfel e identic cu RA.
cat > /tmp/aegis_poison_proxy.py <<'PY'
import http.server, json, urllib.request, os
UP="http://127.0.0.1:8545"; FLAG="/tmp/aegis_poison_ON"
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_POST(self):
        body=self.rfile.read(int(self.headers["Content-Length"]))
        req=urllib.request.Request(UP,data=body,headers={"Content-Type":"application/json"})
        resp=urllib.request.urlopen(req).read()
        if os.path.exists(FLAG):
            try:
                d=json.loads(resp)
                r=d.get("result")
                if isinstance(r,dict) and "hash" in r and r["hash"]:
                    r["hash"]="0x"+"de"*32  # hash fals => divergență
                    resp=json.dumps(d).encode()
            except Exception: pass
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(resp))); self.end_headers(); self.wfile.write(resp)
http.server.HTTPServer(("127.0.0.1",8549),H).serve_forever()
PY
rm -f /tmp/aegis_poison_ON
python3 /tmp/aegis_poison_proxy.py & PROXY_PID=$!; sleep 1

(cd "$E" && cargo build --release -q) || exit 1
BIN="$E/target/release/engine"
cd "$C"; forge build >/dev/null 2>&1
SRC=$(forge script script/DeployCrossChain.s.sol:DeployChainA --rpc-url $RA --broadcast --non-interactive 2>&1 | awk '/deployed at/{print $NF}')
BRG=$(forge script script/DeployCrossChain.s.sol:DeployChainB --rpc-url $RB --broadcast --non-interactive 2>&1 | awk '/deployed at/{print $NF}')
say "Sursă: $SRC | Firewall: $BRG | guardianul citește prin: 8545, 8545, 8549(proxy)"

# 3 URL-uri: două directe la nodul onest + proxy-ul. Când proxy e curat: 3/3 identice.
SRC_RPCS="$RA,$RA,$PROXY" DST_RPC=$RB SRC_CONTRACT=$SRC BRIDGE=$BRG \
  GUARDIAN_KEY=0x0000000000000000000000000000000000000000000000000000000000001111 \
  K=$K SET_ID=1 RPC_QUORUM=3 ATTEST_DIR=$ATT POLL_MS=250 \
  "$BIN" guardian > "$LOGS/guardian.log" 2>&1 &
D+=($!); sleep 2
grep -h online "$LOGS/guardian.log" | sed 's/^/  /'
mine(){ for _ in $(seq "$1"); do cast rpc evm_mine --rpc-url $RA >/dev/null; done; }

phase "A. Toate 3 sursele RPC de acord (proxy curat) → semnează"
cast send --async "$SRC" "deposit(address,uint256)" "$ALICE" 10000000000000000000 --rpc-url $RA --private-key $DEPLOYER >/dev/null
mine $K; sleep 3
MH_A=$(grep -oE 'msg 0x[0-9a-f]+' "$LOGS/guardian.log" | head -1 | awk '{print $2}')
if grep -q 'SIGNED' "$LOGS/guardian.log"; then say "${GRN}✔ SIGNED (consens 3/3)${NC}"
else say "${RED}✘ nu a semnat (ar fi trebuit)${NC}"; fi

phase "B. Activăm otrăvirea proxy-ului → un RPC raportează alt hash"
touch /tmp/aegis_poison_ON
cast send --async "$SRC" "deposit(address,uint256)" "$ALICE" 25000000000000000000 --rpc-url $RA --private-key $DEPLOYER >/dev/null
mine $K; sleep 4
if grep -q 'RPC-POISON' "$LOGS/guardian.log"; then
  say "${GRN}✔ Divergență RPC detectată → REFUZ de semnare${NC}"
  grep 'RPC-POISON' "$LOGS/guardian.log" | tail -1 | sed 's/^/    /'
else say "${RED}✘ Divergența nu a fost detectată${NC}"; fi

phase "Rezumat jurnal"
grep -E 'SIGNED|RPC-POISON' "$LOGS/guardian.log" | sort -u | sed 's/^/  /'
