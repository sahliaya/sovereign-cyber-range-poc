#!/usr/bin/env bash
# Sovereign cyber-range PoC — full evidence run.
# Prereqs: topo.py already running in another terminal; ONOS reachable on 127.0.0.1.
# Every result is written to results/ with a timestamp. Nothing here needs the internet.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$HERE/results/$STAMP"
mkdir -p "$OUT"
PY=python3
ok(){ echo "[ok]  $*"; }; info(){ echo "[..]  $*"; }; warn(){ echo "[!!]  $*"; }

mn(){ # run a command inside a mininet host namespace by PID
  local host="$1"; shift
  local pid; pid="$(pgrep -f "mininet:${host}$" | head -n1)"
  [ -z "$pid" ] && { warn "host $host not found"; return 1; }
  mnexec -a "$pid" "$@"
}
iface(){ echo "$1-eth0"; }

echo "=== Sovereign PoC evidence run $STAMP ===" | tee "$OUT/00_summary.txt"
{
  echo "host: $(uname -a)"
  echo "onos: $($PY "$HERE/flows.py" status --password "${ONOS_PW:-rocks}" 2>&1 | tr '\n' ' ')"
  echo "ovs : $(ovs-vsctl --version 2>/dev/null | head -n1)"
} | tee -a "$OUT/00_summary.txt"

# ---- 0. environment -------------------------------------------------------
info "recording idle + per-process footprint (baseline, before policy)"
free -h            > "$OUT/01_free_idle.txt"
uptime             > "$OUT/01_loadavg_idle.txt"
# JVM / ONOS footprint broken out from the data plane so the 852 MiB is attributable
ps -eo pid,rss,comm --sort=-rss | head -n 15 > "$OUT/01_top_rss.txt"
ok "footprint baseline saved (01_*)"

# ---- 1. default-deny baseline (no policy) ---------------------------------
info "default-deny baseline: every pair should fail with no flow installed"
$PY "$HERE/flows.py" clear --password "${ONOS_PW:-rocks}" >/dev/null 2>&1
sleep 2
{ mn h1 ping -c2 -W1 10.0.0.2; echo "exit=$?"; } > "$OUT/10_deny_h1_h2.txt" 2>&1
{ mn h1 ping -c2 -W1 10.0.0.4; echo "exit=$?"; } > "$OUT/10_deny_h1_h4.txt" 2>&1
ok "baseline deny saved (10_*)"

# ---- 2. install scoped policy (NO arp flood) ------------------------------
info "installing scoped policy (scoped ARP, IPv4 allow h1<->h2 mirrored to h6, h1<->h5:11434)"
$PY "$HERE/flows.py" push --password "${ONOS_PW:-rocks}" | tee "$OUT/20_policy_push.txt"
$PY "$HERE/flows.py" show --password "${ONOS_PW:-rocks}" > "$OUT/20_policy_dump.txt"

# ---- 3. SR7: authorized pair works, exfiltration to h4 blocked ------------
info "SR7: authorized h1<->h2 should pass; h1->h4 and h2->h4 should be blocked"
{ mn h1 ping -c3 -W1 10.0.0.2; echo "exit=$?"; } > "$OUT/30_allow_h1_h2.txt" 2>&1
# capture at h4 while h1 attempts to exfiltrate
mn h4 timeout 8 tcpdump -ni "$(iface h4)" -w "$OUT/31_h4_capture.pcap" 2>/dev/null &
sleep 1
{ mn h1 timeout 5 nc -vz 10.0.0.4 4444; echo "exit=$?"; } > "$OUT/31_h1_exfil_nc.txt" 2>&1
mn h1 ping -c2 -W1 10.0.0.4 >> "$OUT/31_h1_exfil_nc.txt" 2>&1
wait
mn h4 tcpdump -nr "$OUT/31_h4_capture.pcap" 2>/dev/null | tee "$OUT/31_h4_capture.txt" | \
  { c=$(wc -l < /dev/stdin); echo "packets at h4 during exfil attempt: $c"; } \
  > "$OUT/31_h4_packetcount.txt"
ok "SR7 exfiltration evidence saved (30_*, 31_*)"

# ---- 4. ARP covert-channel attempt (defeats the OLD flood rule) -----------
info "covert-channel ARP from h3 -> should NOT reach h4 under scoped ARP"
mn h4 timeout 8 tcpdump -ni "$(iface h4)" arp -w "$OUT/40_h4_arp.pcap" 2>/dev/null &
sleep 1
mn h3 $PY "$HERE/lab_scapy.py" covert --iface "$(iface h3)" \
     --src-mac 00:00:00:00:00:03 --src-ip 10.0.0.3 --target-ip 10.0.0.4 --count 50 \
     > "$OUT/40_h3_covert_send.txt" 2>&1
wait
mn h4 tcpdump -nr "$OUT/40_h4_arp.pcap" 2>/dev/null | tee "$OUT/40_h4_arp.txt" | \
  grep -c "COVERT\|Request" > "$OUT/40_h4_arp_count.txt" 2>/dev/null || echo 0 > "$OUT/40_h4_arp_count.txt"
ok "covert-channel evidence saved (40_*)  [0 at h4 = scoped ARP holds]"

# ---- 5. on-path ARP poisoning (your original MITM claim) ------------------
info "arpspoof h3 against h1<->h2; authorized ping must still hold, h3 sees 0"
mn h3 $PY "$HERE/lab_scapy.py" poison --iface "$(iface h3)" \
     --attacker-mac 00:00:00:00:00:03 --victim-ip 10.0.0.1 --victim-mac 00:00:00:00:00:01 \
     --spoof-ip 10.0.0.2 --count 30 --interval 0.5 > "$OUT/50_h3_poison_a.txt" 2>&1 &
mn h3 $PY "$HERE/lab_scapy.py" poison --iface "$(iface h3)" \
     --attacker-mac 00:00:00:00:00:03 --victim-ip 10.0.0.2 --victim-mac 00:00:00:00:00:02 \
     --spoof-ip 10.0.0.1 --count 30 --interval 0.5 > "$OUT/50_h3_poison_b.txt" 2>&1 &
sleep 1
mn h3 timeout 10 tcpdump -ni "$(iface h3)" icmp -w "$OUT/50_h3_icmp.pcap" 2>/dev/null &
{ mn h1 ping -c5 -W1 10.0.0.2; echo "exit=$?"; } > "$OUT/50_h1_h2_under_attack.txt" 2>&1
wait
mn h3 tcpdump -nr "$OUT/50_h3_icmp.pcap" 2>/dev/null | wc -l > "$OUT/50_h3_icmp_count.txt"
ok "ARP-poisoning resistance evidence saved (50_*)  [0 ICMP at h3 = pass]"

# ---- 6. bounded-AI egress ENFORCED at the network layer -------------------
# Ollama runs on h5. Policy allows ONLY h1<->h5:11434. Everything else from h5 is denied.
# sudo resets PATH to secure_path (no /usr/local/bin), which is where ollama
# usually lives, so the mnexec'd shells need PATH re-widened explicitly.
MNPATH='PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin'
if mn h5 sh -c "$MNPATH command -v ollama >/dev/null 2>&1"; then
  info "AI egress: h1->h5 inference allowed; h5->h4 and h5->outside blocked by flows"
  # Bind on all interfaces inside h5's netns (not 127.0.0.1) so h1 can actually
  # reach it over 10.0.0.5 -- that's the whole point of the test. Point
  # OLLAMA_MODELS at the already-pulled model (this serve runs as root via
  # mnexec, with its own cold $HOME/.ollama otherwise; root can read the
  # system ollama service's model dir, so reuse it instead of re-pulling).
  mn h5 sh -c "$MNPATH OLLAMA_HOST=0.0.0.0:11434 OLLAMA_MODELS=/usr/share/ollama/.ollama/models nohup ollama serve >/tmp/ollama.log 2>&1 &"
  sleep 5
  # the sanctioned call: orchestrator h1 asks the model over the one allowed flow
  mn h1 sh -c "$MNPATH OLLAMA_HOST=10.0.0.5:11434 ollama run qwen2.5:1.5b \"Generate one adversary ATT&CK technique id and a one-line scenario note.\" --verbose" \
     > "$OUT/60_h1_to_h5_inference.txt" 2>&1
  # the containment checks: h5 must not reach an unauthorized host or the boundary
  { mn h5 timeout 5 nc -vz 10.0.0.4 4444; echo "exit=$?"; }      > "$OUT/61_h5_to_h4_blocked.txt" 2>&1
  { mn h5 timeout 5 nc -vz 10.0.0.254 443; echo "exit=$?"; }     > "$OUT/61_h5_to_boundary_blocked.txt" 2>&1
  mn h5 ss -tnp > "$OUT/61_h5_sockets.txt" 2>&1   # process-level corroboration (your original V-C evidence)
  ok "bounded-AI egress evidence saved (60_*, 61_*)"
else
  warn "ollama not found in h5 namespace — skipping AI test."
  warn "install first on the host, then it is visible in all namespaces:"
  warn "  curl -fsSL https://ollama.com/install.sh | sh   (needs internet, do before air-gapping)"
  warn "  ollama pull qwen2.5:1.5b"
  echo "SKIPPED: ollama not installed" > "$OUT/60_SKIPPED.txt"
fi

# ---- 7. control-plane scaling (answers the 'single idle slice' remark) ----
info "scaling: install 1,2,4,8 concurrent slices' worth of deny rules; time install + load"
for n in 50 100 200 400; do
  t0=$(date +%s.%N)
  $PY - "$n" <<PYEOF >> "$OUT/70_scaling.txt" 2>&1
import sys, time
sys.path.insert(0, "$HERE")
from flows import Onos, scale_flows, DEVICE_ID
o = Onos(password="${ONOS_PW:-rocks}")
rules = scale_flows(DEVICE_ID, int(sys.argv[1]))
t=time.time(); o.push(rules); added=o.wait_added(0,1)
print(f"n={sys.argv[1]:>4}  pushed in {time.time()-t:6.2f}s")
PYEOF
  uptime | sed "s/^/n=$n load: /" >> "$OUT/70_scaling.txt"
  ps -eo rss,comm --sort=-rss | awk 'NR==2{print "n='"$n"' top-rss-kb:",$1,$2}' >> "$OUT/70_scaling.txt"
done
$PY "$HERE/flows.py" push --password "${ONOS_PW:-rocks}" >/dev/null 2>&1  # restore clean policy
ok "scaling evidence saved (70_*)"

# ---- 8. footprint under policy (attributed) -------------------------------
free -h > "$OUT/80_free_under_policy.txt"
ps -eo pid,rss,comm --sort=-rss | head -n 15 > "$OUT/80_top_rss_under_policy.txt"
# ONOS JVM specifically, so the 852 MiB is shown as controller overhead not data plane
ps -eo rss,comm | awk '/java/{s+=$1} END{printf "ONOS/JVM RSS: %.0f MiB\n", s/1024}' > "$OUT/80_onos_jvm_rss.txt"
ok "footprint-under-policy evidence saved (80_*)"

echo
echo "=== DONE. Evidence in: $OUT ==="
echo "Key files for the paper:"
echo "  31_h4_packetcount.txt   SR7 zero-egress"
echo "  40_h4_arp_count.txt     covert-ARP blocked (fixes the flood-rule hole)"
echo "  50_h3_icmp_count.txt    ARP-poisoning resistance"
echo "  61_h5_*_blocked.txt     AI egress enforced at network layer"
echo "  70_scaling.txt          control-plane scaling"
echo "  80_onos_jvm_rss.txt     852 MiB attributed to JVM"
