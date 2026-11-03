#!/usr/bin/env bash
# Sovereign cyber-range PoC -- VyOS router/firewall NFV evidence run, part 1/2.
#
# Second, ACTIVE NFV function (complementing Suricata's passive IDS mirror,
# suricata/run_suricata_test.sh): VyOS routes and firewalls between h7
# (boundary gateway stand-in) and a simulated "outside" host (hcap),
# demonstrating default-deny enforced by the virtualized network function
# itself, not only by the OVS/ONOS flow layer.
#
# This script does the scriptable, reliable half: tap/netns/OVS wiring,
# routes, and the ONOS flows. Boot and configure VyOS yourself with
# vyos_console_commands.txt (console interaction can't safely run unattended
# alongside a live qemu session in a portable way -- same reason the
# project's very first PoC used step-by-step .txt files for Mininet CLI
# work), then come back and run run_vyos_nfv_test_2.sh for the actual
# evidence capture.
#
# Topology addition on top of the normal single-slice run (topo.py --test):
#   h7 (10.0.0.254) --- vyos-in (10.0.0.9, OVS port 8)
#   VyOS routes/firewalls between its two interfaces
#   vyos-out (203.0.113.9, OVS port 9) --- hcap (203.0.113.10, OVS port 10)
#
# Prereqs: topo.py --test already running (single slice, h1..h7), ONOS
# reachable on 127.0.0.1, lab_policy already pushed (flows.py push).
# Run with sudo. Needs: qemu-system-x86_64 (KVM), ovs-vsctl, ip.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$HERE")"
ok(){ echo "[ok]  $*"; }; info(){ echo "[..]  $*"; }; warn(){ echo "[!!]  $*"; }

if [ "$EUID" -ne 0 ]; then warn "run with sudo"; exit 1; fi

# ---- 1. tap interfaces for VyOS, attached to the existing single-slice switch s1 ----
info "creating VyOS tap interfaces and attaching to s1"
ip tuntap add dev vyos-in  mode tap user "${SUDO_USER:-root}" 2>/dev/null
ip tuntap add dev vyos-out mode tap user "${SUDO_USER:-root}" 2>/dev/null
ip link set vyos-in up
ip link set vyos-out up
ovs-vsctl add-port s1 vyos-in  2>/dev/null
ovs-vsctl add-port s1 vyos-out 2>/dev/null

# ---- 2. hcap: the "beyond the boundary" host, plain netns + veth into s1 -----------
info "creating hcap (outside) network namespace"
ip netns add hcap 2>/dev/null
ip link add hcap-eth0 type veth peer name s1-hcap 2>/dev/null
ip link set hcap-eth0 netns hcap 2>/dev/null
ip netns exec hcap ip link set hcap-eth0 address 00:00:00:00:00:0a
ip netns exec hcap ip addr add 203.0.113.10/24 dev hcap-eth0 2>/dev/null
ip netns exec hcap ip link set hcap-eth0 up
ip netns exec hcap ip link set lo up
ip link set s1-hcap up
ovs-vsctl add-port s1 s1-hcap 2>/dev/null
ok "tap/netns topology extension ready (ports: vyos-in, vyos-out, s1-hcap)"

# ---- 3. routes: h7 -> outside subnet via VyOS; hcap -> inside subnet via VyOS -----
ip netns exec hcap ip route add 10.0.0.0/24 via 203.0.113.9 2>/dev/null
mnexec -a "$(pgrep -f 'mininet:h7$' | head -n1)" ip route add 203.0.113.0/24 via 10.0.0.9 2>/dev/null
ok "routes added (h7 -> 203.0.113.0/24 via vyos-in; hcap -> 10.0.0.0/24 via vyos-out)"

# ---- 4. ONOS flows: gateway-style ALLOW (no dest-IP match -- VyOS, not the switch, ---
#         makes the L3/firewall decision), plus the already-fixed non-flooding ARP ----
info "pushing ONOS gateway flows for h7<->vyos-in and vyos-out<->hcap"
python3 - "$REPO" <<'PYEOF'
import sys
repo = sys.argv[1]
sys.path.insert(0, repo)
from flows import Onos, flow, crit, out as fout, arp_allow, PRIO_ALLOW, DEVICE_ID, HOSTS

nfv_hosts = dict(HOSTS)
nfv_hosts["vyos-in"]  = (8,  "10.0.0.9",     "52:54:00:00:00:08", "VyOS inside iface")
nfv_hosts["vyos-out"] = (9,  "203.0.113.9",  "52:54:00:00:00:09", "VyOS outside iface")
nfv_hosts["hcap"]     = (10, "203.0.113.10", "00:00:00:00:00:0a", "outside capture host")

def gateway_allow(dev, a, b, hosts):
    """Allow any IPv4 from a's port/MAC out to b's port -- no destination-IP
    restriction, since b is acting as a gateway/VNF doing its own L3 routing
    and firewalling, not a fixed communication peer. (A narrower, exact-IP
    ipv4_allow() flow here only matches traffic addressed TO the gateway's
    own interface, not traffic transiting THROUGH it -- the bug this run
    hit and fixed on first try.)"""
    pa, _, ma, _ = hosts[a]
    pb = hosts[b][0]
    return flow(dev, PRIO_ALLOW,
                [crit("IN_PORT", port=pa), crit("ETH_SRC", mac=ma),
                 crit("ETH_TYPE", ethType="0x0800")],
                [fout(pb)])

flows = [
    gateway_allow(DEVICE_ID, "h7", "vyos-in", nfv_hosts),
    gateway_allow(DEVICE_ID, "vyos-in", "h7", nfv_hosts),
    gateway_allow(DEVICE_ID, "vyos-out", "hcap", nfv_hosts),
    gateway_allow(DEVICE_ID, "hcap", "vyos-out", nfv_hosts),
    arp_allow(DEVICE_ID, nfv_hosts, "h7", ["vyos-in"]),
    arp_allow(DEVICE_ID, nfv_hosts, "vyos-in", ["h7"]),
    arp_allow(DEVICE_ID, nfv_hosts, "vyos-out", ["hcap"]),
    arp_allow(DEVICE_ID, nfv_hosts, "hcap", ["vyos-out"]),
]
o = Onos(password="rocks")
o.req("POST", "/flows?appId=org.onosproject.cli", {"flows": flows})
print(f"pushed {len(flows)} flows")
PYEOF
ok "ONOS flows installed"

echo
echo "=== Part 1 done. Next: ==="
echo "  1. In a new terminal, boot VyOS:"
echo "     qemu-system-x86_64 -enable-kvm -m 1024 -smp 1 \\"
echo "       -cdrom $HERE/vyos-rolling-generic-amd64.iso -boot d \\"
echo "       -netdev tap,id=net0,ifname=vyos-in,script=no,downscript=no \\"
echo "       -device virtio-net-pci,netdev=net0,mac=52:54:00:00:00:08 \\"
echo "       -netdev tap,id=net1,ifname=vyos-out,script=no,downscript=no \\"
echo "       -device virtio-net-pci,netdev=net1,mac=52:54:00:00:00:09 \\"
echo "       -nographic -serial mon:stdio"
echo "  2. Log in (vyos/vyos) and run the commands in vyos_console_commands.txt"
echo "  3. Once committed, run: sudo ./run_vyos_nfv_test_2.sh"
