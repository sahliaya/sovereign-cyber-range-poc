#!/usr/bin/env bash
# NFV evidence: run Suricata inside h6's netns against the mirrored h1<->h2
# traffic, trigger it with real ICMP, show the alert. Run with sudo.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/out}"
mkdir -p "$OUT"

nspid(){
  pgrep -f "mininet:${1}$" | head -n1
}

echo "[..] starting suricata in h6 namespace on h6-eth0"
timeout 12 mnexec -a "$(nspid h6)" suricata -i h6-eth0 -S "$HERE/local.rules" -l "$OUT" --runmode single >"$OUT/suricata_stdout.log" 2>&1 &
SURI_BG=$!
sleep 3

echo "[..] generating h1<->h2 ICMP traffic (mirrored to h6 by the ipv4_allow flow)"
mnexec -a "$(nspid h1)" ping -c5 -W1 10.0.0.2 > "$OUT/h1_h2_ping.txt" 2>&1

sleep 2
wait "$SURI_BG" 2>/dev/null

echo "[..] result:"
if [ -s "$OUT/fast.log" ]; then
  echo "[ok] fast.log has alerts:"
  cat "$OUT/fast.log"
else
  echo "[!!] no fast.log / no alerts -- check $OUT/suricata_stdout.log and $OUT/eve.json"
fi
