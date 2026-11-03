#!/usr/bin/env bash
# Sovereign cyber-range PoC -- multi-slice concurrent-load evidence run.
#
# Answers the reviewer remark: "Evaluating a single L2 slice with four idle
# Mininet processes ... does not test whether the control plane or commodity
# host can sustain realistic cyber-range workloads" when several training
# exercises run at once.
#
# Prereqs: topo.py already running with N slices in another terminal:
#   sudo python3 topo.py --slices 4 --test
# ONOS reachable on 127.0.0.1. Run this with sudo (mnexec needs root).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
N="${SLICES:-4}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$HERE/results/multislice-$STAMP"
mkdir -p "$OUT"
PY=python3
ok(){ echo "[ok]  $*"; }; info(){ echo "[..]  $*"; }; warn(){ echo "[!!]  $*"; }

nspid(){ pgrep -f "mininet:${1}$" | head -n1; }
mn(){ local host="$1"; shift; local pid; pid="$(nspid "$host")"
  [ -z "$pid" ] && { warn "host $host not found"; return 1; }
  mnexec -a "$pid" "$@"
}
hn(){ echo "h$1s$2"; }        # host name for role (1..7) in slice i
ip4(){ echo "10.0.$2.$([ "$1" = 7 ] && echo 254 || echo "$1")"; }  # matching flows.make_hosts

if [ "$N" -lt 2 ]; then
  warn "this script is for N>=2 concurrent slices (topo.py --slices $N uses unsuffixed 'h1'..'h7');"
  warn "for a single slice use run_tests.sh instead. Set SLICES=4 ./run_multislice_test.sh."
  exit 1
fi

echo "=== Sovereign PoC multi-slice evidence run $STAMP (N=$N slices) ===" | tee "$OUT/00_summary.txt"
{
  echo "host: $(uname -a)"
  echo "slices requested: $N"
  echo "onos: $($PY "$HERE/flows.py" status --slices "$N" --password "${ONOS_PW:-rocks}" 2>&1 | tr '\n' ' ')"
} | tee -a "$OUT/00_summary.txt"

# ---- 0. all N slice devices must be connected before we start -----------
info "waiting for all $N slice devices to connect to ONOS"
if ! $PY - "$N" <<PYEOF
import sys
sys.path.insert(0, "$HERE")
from flows import Onos
o = Onos(password="${ONOS_PW:-rocks}")
ok = o.all_devices_available(int(sys.argv[1]), timeout=60)
print("all devices available:", ok)
sys.exit(0 if ok else 1)
PYEOF
then
  warn "not all $N slice devices connected -- is topo.py running with --slices $N?"
  exit 1
fi
ok "all $N slice devices connected"

# ---- 1. provision all N slices in ONE batched push, time it -------------
info "pushing policy to all $N slices in a single ONOS REST batch"
t0=$(date +%s.%N)
$PY "$HERE/flows.py" push --slices "$N" --password "${ONOS_PW:-rocks}" | tee "$OUT/10_multislice_push.txt"
echo "wall time: $(echo "$(date +%s.%N) - $t0" | bc)s" | tee -a "$OUT/10_multislice_push.txt"
$PY "$HERE/flows.py" show --slices "$N" --password "${ONOS_PW:-rocks}" > "$OUT/10_multislice_dump.txt"

# ---- 2. concurrent load across ALL N slices at once ----------------------
# This is the core evidence: every slice's authorized pair pinging, every
# slice's attacker simultaneously attempting exfiltration AND an ARP
# covert-channel attempt, all at the same time -- not sequential, not idle.
info "launching concurrent authorized + attack traffic on all $N slices at once"
free -h > "$OUT/20_free_before_load.txt"

for i in $(seq 0 $((N - 1))); do
  { mn "$(hn 1 $i)" ping -c6 -W1 "$(ip4 2 $i)"; echo "exit=$?"; } > "$OUT/30_s${i}_allow_h1_h2.txt" 2>&1 &
  { mn "$(hn 1 $i)" timeout 6 nc -vz "$(ip4 4 $i)" 4444; echo "exit=$?"; } > "$OUT/31_s${i}_exfil_nc.txt" 2>&1 &
  mn "$(hn 4 $i)" timeout 8 tcpdump -ni "$(hn 4 $i)-eth0" -w "$OUT/31_s${i}_h4_capture.pcap" 2>/dev/null &
  mn "$(hn 4 $i)" timeout 8 tcpdump -ni "$(hn 4 $i)-eth0" arp -w "$OUT/40_s${i}_h4_arp.pcap" 2>/dev/null &
  mn "$(hn 3 $i)" "$PY" "$HERE/lab_scapy.py" covert --iface "$(hn 3 $i)-eth0" \
       --src-mac "00:00:00:0$i:00:03" --src-ip "$(ip4 3 $i)" --target-ip "$(ip4 4 $i)" --count 50 \
       > "$OUT/40_s${i}_covert_send.txt" 2>&1 &
done
# record footprint WHILE all N slices are concurrently loaded (not idle)
sleep 3
ps -eo pid,rss,comm --sort=-rss | head -n 15 > "$OUT/21_top_rss_under_concurrent_load.txt"
uptime > "$OUT/21_loadavg_under_concurrent_load.txt"
wait
ok "concurrent multi-slice traffic saved (30_*, 31_*, 40_*)"

for i in $(seq 0 $((N - 1))); do
  mn "$(hn 4 $i)" tcpdump -nr "$OUT/31_s${i}_h4_capture.pcap" 2>/dev/null > "$OUT/31_s${i}_h4_capture.txt"
  mn "$(hn 4 $i)" tcpdump -nr "$OUT/40_s${i}_h4_arp.pcap" 2>/dev/null | \
    grep -c "COVERT\|Request" > "$OUT/40_s${i}_h4_arp_count.txt" 2>/dev/null || echo 0 > "$OUT/40_s${i}_h4_arp_count.txt"
done

# ---- 3. structural cross-slice isolation (exercise i cannot reach j) -----
info "cross-slice isolation: h1 in slice 0 attempts slice 1's h1 (different switch entirely)"
if [ "$N" -ge 2 ]; then
  { mn "$(hn 1 0)" timeout 5 ping -c3 -W1 "$(ip4 1 1)"; echo "exit=$?"; } > "$OUT/50_cross_slice_isolation.txt" 2>&1
fi
ok "cross-slice isolation evidence saved (50_*)"

# ---- 4. footprint back at rest, for comparison ----------------------------
free -h > "$OUT/80_free_after_load.txt"
ps -eo pid,rss,comm --sort=-rss | head -n 15 > "$OUT/80_top_rss_after_load.txt"
ps -eo rss,comm | awk '/java/{s+=$1} END{printf "ONOS/JVM RSS: %.0f MiB\n", s/1024}' > "$OUT/80_onos_jvm_rss_after_load.txt"

echo
echo "=== DONE. Evidence in: $OUT ==="
echo "Key files:"
echo "  10_multislice_push.txt            all $N slices provisioned in one batch, timed"
echo "  21_*_under_concurrent_load.txt    footprint while all $N slices are simultaneously loaded"
echo "  31_s*_h4_capture.txt / 40_s*_arp_count.txt   per-slice SR7 + covert-ARP, all held under concurrency"
echo "  50_cross_slice_isolation.txt      exercise-to-exercise isolation (structural, not just policy)"
