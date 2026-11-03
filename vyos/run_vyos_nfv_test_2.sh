#!/usr/bin/env bash
# Sovereign cyber-range PoC -- VyOS router/firewall NFV evidence run, part 2/2.
# Run after run_vyos_nfv_test.sh (part 1) and the console commands in
# vyos_console_commands.txt have been committed on VyOS. Leave VyOS running.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$HERE")"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$REPO/results/vyos-$STAMP"
mkdir -p "$OUT"
ok(){ echo "[ok]  $*"; }; info(){ echo "[..]  $*"; }; warn(){ echo "[!!]  $*"; }

if [ "$EUID" -ne 0 ]; then warn "run with sudo"; exit 1; fi

echo "=== VyOS NFV router/firewall evidence run $STAMP ===" | tee "$OUT/00_summary.txt"
{
  echo "Second, active NFV function (router+stateful firewall), complementing"
  echo "the passive Suricata IDS mirror (sec:poc-nfv). h7 -> vyos-in -> VyOS"
  echo "routing/firewall -> vyos-out -> hcap (simulated outside host)."
} | tee -a "$OUT/00_summary.txt"

info "VyOS interface state"
sudo -u "${SUDO_USER:-root}" true 2>/dev/null  # no-op, keep shellcheck quiet

info "ONOS flows on the new ports (8=vyos-in, 9=vyos-out, 10=hcap)"
python3 - "$REPO" "$OUT" <<'PYEOF'
import sys
repo, out = sys.argv[1], sys.argv[2]
sys.path.insert(0, repo)
from flows import Onos, DEVICE_ID
o = Onos(password="rocks")
dump = o.req("GET", f"/flows/{DEVICE_ID}")
with open(f"{out}/20_onos_flows_vyos_ports.txt", "w") as fh:
    for f in dump["flows"]:
        crits = f["selector"]["criteria"]
        in_port = next((c for c in crits if c["type"] == "IN_PORT"), None)
        if in_port and str(in_port.get("port")) in ("8", "9", "10"):
            ethtype = next((c for c in crits if c["type"] == "ETH_TYPE"), None)
            fh.write(f"{f['state']} in_port={in_port['port']} "
                      f"ethType={ethtype['ethType'] if ethtype else None} "
                      f"prio={f['priority']}\n")
PYEOF
ok "flow dump saved (20_*)"

info "TEST 1: legitimate path, h7 -> hcap through VyOS (expect 0% loss)"
mnexec -a "$(pgrep -f 'mininet:h7$' | head -n1)" ping -c3 -W2 203.0.113.10 \
  > "$OUT/30_legit_ping_h7_to_hcap.txt" 2>&1
cat "$OUT/30_legit_ping_h7_to_hcap.txt"

info "TEST 2: unsolicited TCP from outside (hcap) to inside (h7) -- expect timeout, not refused"
ip netns exec hcap timeout 5 nc -vz -w3 10.0.0.254 4444 > "$OUT/40_unsolicited_tcp_hcap_to_h7.txt" 2>&1
echo "exit=$?" >> "$OUT/40_unsolicited_tcp_hcap_to_h7.txt"
cat "$OUT/40_unsolicited_tcp_hcap_to_h7.txt"

info "TEST 3: unsolicited ICMP from outside (hcap) to inside (h7) -- expect 100% loss"
ip netns exec hcap ping -c3 -W2 10.0.0.254 > "$OUT/41_unsolicited_icmp_hcap_to_h7.txt" 2>&1
cat "$OUT/41_unsolicited_icmp_hcap_to_h7.txt"

ok "host-side tests saved (30_*, 40_*, 41_*)"
echo
echo "=== Now go back to the VyOS console and run: ==="
echo "    show log firewall"
echo "Save its output as: $OUT/50_vyos_firewall_log.txt"
echo "Then 'poweroff' VyOS to end the test cleanly."
