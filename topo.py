#!/usr/bin/env python3
"""
Sovereign cyber-range PoC topology: N independent OVS switches (N concurrent
"slices"), each with its own ONOS device ID and its own seven hosts with
pinned MACs so the per-slice ONOS flow selectors in flows.py match.

  h1  authorized host / orchestrator      port 1
  h2  authorized peer                      port 2
  h3  on-path attacker (arpspoof)          port 3
  h4  unauthorized destination             port 4
  h5  bounded-AI host (Ollama)             port 5
  h6  IDS function (Suricata on mirror)    port 6
  h7  boundary gateway (outside stand-in)  port 7

With --slices 1 (the default), host names are exactly h1..h7 on switch s1,
dpid 0000000000000001 -- byte-identical to the original single-slice
topology, so the existing run_tests.sh evidence run is unaffected.

With --slices N>1, each slice i gets its own switch s<i+1> (own dpid, own
ONOS device) and its own host set named h1s<i>..h7s<i> on its own /24
(10.0.<i>.x) -- N independent L2 broadcast domains with no link between
them, so isolation across concurrently-active slices is structural, not
just policy. This is what the multi-slice test
(run_multislice_test.sh) uses to show the control plane holds under
several *concurrently loaded* slices rather than one idle one.

Run:  sudo python3 topo.py                     # interactive CLI, 1 slice
      sudo python3 topo.py --test               # 1 slice, hand off to run_tests.sh
      sudo python3 topo.py --slices 4 --test     # 4 concurrent slices
OVS is forced to OpenFlow 1.3 and fail-secure so that, with no flow installed,
the default state is deny (nothing is forwarded) rather than a legacy L2 flood.
"""
import argparse

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink

from flows import make_hosts, dpid_hex


def host_name(name, slice_idx, n_slices):
    return name if n_slices == 1 else f"{name}s{slice_idx}"


def build(controller_ip="127.0.0.1", n_slices=1):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=False)
    c0 = net.addController("c0", controller=RemoteController, ip=controller_ip, port=6653)
    switches = []
    for i in range(n_slices):
        sw_name = "s1" if n_slices == 1 else f"s{i + 1}"
        sw = net.addSwitch(sw_name, protocols="OpenFlow13", failMode="secure", dpid=dpid_hex(i))
        switches.append(sw)
        for name, (port, ip, mac, role) in make_hosts(i).items():
            h = net.addHost(host_name(name, i, n_slices), ip=ip + "/24", mac=mac)
            net.addLink(h, sw)
    net.build()
    c0.start()
    for sw in switches:
        sw.start([c0])
    return net


if __name__ == "__main__":
    setLogLevel("info")
    ap = argparse.ArgumentParser()
    ap.add_argument("--controller", default="127.0.0.1")
    ap.add_argument("--slices", type=int, default=1,
                     help="number of independent concurrent L2 slices to build (default 1)")
    ap.add_argument("--test", action="store_true", help="build and exit (leave net up for the harness)")
    args = ap.parse_args()
    net = build(args.controller, args.slices)
    if not args.test:
        CLI(net)
        net.stop()
    else:
        print(f"Topology up: {args.slices} slice(s). Default state is deny (fail-secure, no flows). "
              "Run ./run_tests.sh (1 slice) or ./run_multislice_test.sh (N slices), "
              "then 'sudo mn -c' to clean up.")
        CLI(net)
        net.stop()
