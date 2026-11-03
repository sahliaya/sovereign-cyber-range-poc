# Sovereign SDN/NFV Cyber Range — PoC Reproduction Scripts

Reproduction material for the proof-of-concept reported in *Toward a
Sovereign SDN/NFV Cyber Range: A Reference Architecture and Feasibility
Proof-of-Concept* (Section V, `main.tex`). Everything here runs on a single
commodity laptop with Mininet, Open vSwitch, and ONOS — no cloud, no
external service except the one-time Ollama install (do that before
air-gapping).

This repository is the reference implementation for every Section V
sub-test, including everything closed since the first CommNet'26 review
round: real NFV (Suricata IDS mirror, VyOS router/firewall), a hardened
ARP policy with no flood rule, AI-egress enforcement at the network layer,
and concurrent multi-slice isolation. If a number appears in the paper, it
was produced by a script in this repository, and the exact output is in
`results/`.

## Requirements

```bash
sudo apt install mininet openvswitch-switch python3-scapy tcpdump netcat-openbsd suricata expect
curl -fsSL https://ollama.com/install.sh | sh   # needs internet; do before air-gapping
ollama pull qwen2.5:1.5b
```

Docker, to run ONOS (`onos/README.md`). QEMU/KVM + libvirt, for the VyOS
NFV sub-test (`qemu-system-x86_64`, `/dev/kvm` present — most Linux desktops
already have this; `sudo apt install qemu-system-x86 libvirt-daemon-system`
if not).

## Layout

```
onos/README.md                 ONOS controller setup (Docker)
topo.py                        Mininet topology: 1 or N independent slices
flows.py                       ONOS REST client + flow-policy builder (CLI)
lab_scapy.py                   ARP-poisoning and covert-channel traffic generators
run_tests.sh                   Full single-slice evidence run (SR7, MITM, AI egress, footprint)
run_multislice_test.sh         N=4 concurrent multi-slice evidence run
suricata/local.rules           Minimal IDS rule used for the NFV sub-test
suricata/run_suricata_test.sh  Runs Suricata in h6's namespace against mirrored traffic
vyos/run_vyos_nfv_test.sh      Part 1/2: tap/netns/OVS wiring + ONOS flows for the VyOS NFV sub-test
vyos/vyos_console_commands.txt Exact VyOS CLI commands (interfaces, firewall) -- paste into its console
vyos/run_vyos_nfv_test_2.sh    Part 2/2: the actual traffic tests, once VyOS is configured
vyos/vyos-rolling-generic-amd64.iso   VyOS rolling-release ISO (not tracked in git -- see below)
results/20261102-194225/       Reference single-slice evidence run (incl. suricata/)
results/multislice-20261103-113000/   Reference 4-slice concurrent evidence run
results/vyos-20261103-215600/  Reference VyOS NFV router/firewall evidence run
```

## Topology

Seven host roles, pinned MACs, one switch per slice:

| Host | Role | Paper section |
|---|---|---|
| h1 | authorized orchestrator | §V-A, §V-B, §V-C |
| h2 | authorized peer | §V-A, §V-B |
| h3 | on-path attacker (ARP poisoning, covert channel) | §V-A, §V-B |
| h4 | unauthorized destination | §V-A |
| h5 | bounded-AI host (Ollama) | §V-C |
| h6 | IDS function (Suricata, on the h1↔h2 mirror port) | §V-D |
| h7 | boundary gateway stand-in | §V-C |

With `--slices 1` (the default), host names are exactly `h1`..`h7` on
switch `s1`. With `--slices N > 1`, each slice gets its own switch (own
dpid, own ONOS device) and its own `/24`, with no link between slices —
isolation is structural, not just policy.

The VyOS NFV sub-test adds three more ports to `s1` (single-slice only, not
part of `topo.py`'s Mininet-managed hosts): `vyos-in` (10.0.0.9, VyOS's
inside interface, reached from h7), `vyos-out` (203.0.113.9, VyOS's outside
interface), and `hcap` (203.0.113.10, a plain network namespace standing in
for a host beyond the boundary). VyOS routes and firewalls between its two
interfaces; the ONOS flows only deliver packets to/from its ports; the
forwarding decision is VyOS's own.

## Reproduction order

1. **Bring up ONOS:**
   ```bash
   docker run -d --name onos -p 6653:6653 -p 8181:8181 -p 8101:8101 onosproject/onos
   python3 flows.py status   # wait for org.onosproject.openflow: ACTIVE, fwd: INSTALLED (not ACTIVE)
   ```
   `fwd` must stay **INSTALLED, not ACTIVE** — reactive forwarding has to be
   off for default-deny to be real.

2. **Single-slice run** (reproduces §V-A through §V-C, §V-F):
   ```bash
   sudo python3 topo.py --test        # terminal 1, leave the CLI open
   sudo ONOS_PW=rocks ./run_tests.sh  # terminal 2
   sudo mn -c                         # cleanup
   ```

3. **NFV / Suricata run** (reproduces §V-D), with the topology from step 2
   still up and the h1↔h2 ALLOW flow installed:
   ```bash
   sudo ./suricata/run_suricata_test.sh
   ```

4. **Multi-slice concurrent run** (reproduces §V-E):
   ```bash
   sudo python3 topo.py --slices 4 --test   # terminal 1
   sudo SLICES=4 ./run_multislice_test.sh   # terminal 2
   sudo mn -c
   ```

5. **VyOS router/firewall NFV run** (reproduces §V-D's second half), with the
   single-slice topology from step 2 still up:
   ```bash
   sudo ./vyos/run_vyos_nfv_test.sh                    # terminal 2: wiring + ONOS flows
   # terminal 3, foreground/interactive -- boot VyOS with the qemu command
   # part 1 just printed, then paste vyos/vyos_console_commands.txt at its console
   sudo ./vyos/run_vyos_nfv_test_2.sh                  # terminal 2: the actual tests
   # back in terminal 3: `show log firewall`, save the output, then `poweroff`
   ```
   The VyOS ISO isn't tracked in git (600+ MB); download it first:
   ```bash
   curl -L -o vyos/vyos-rolling-generic-amd64.iso \
     "https://downloads.vyos.io/rolling/current/amd64/vyos-rolling-latest.iso"
   # if that 403s (Cloudflare bot check), use the GitHub-hosted nightly build
   # instead -- see the latest release at
   # https://github.com/vyos/vyos-nightly-build/releases
   ```

Read `results/<run>/00_summary.txt` first, then the key files each script
lists at the end of its run.

## Key evidence files (what the paper's numbers come from)

| Claim in the paper | File |
|---|---|
| SR7 zero-egress exfiltration | `results/20261102-194225/31_h4_packetcount.txt` |
| ARP-hardened resistance to active poisoning | `results/20261102-194225/50_h3_icmp_count.txt` |
| ARP covert-channel blocked (no flood rule) | `results/20261102-194225/40_h4_arp_count.txt` |
| Bounded-AI inference works; egress elsewhere refused | `results/20261102-194225/60_h1_to_h5_inference.txt`, `61_h5_to_h4_blocked.txt`, `61_h5_to_boundary_blocked.txt` |
| NFV: real Suricata alert on steered traffic | `results/20261102-194225/suricata/fast.log` |
| Footprint, idle (852 MiB) | `results/20261102-194225/80_onos_jvm_rss.txt` |
| Footprint, 4-slice concurrent load (1045 MiB) | `results/multislice-20261103-113000/80_onos_jvm_rss_after_load.txt` |
| 4 slices provisioned in one batch, timed | `results/multislice-20261103-113000/10_multislice_push.txt` |
| Cross-slice isolation is structural | `results/multislice-20261103-113000/50_cross_slice_isolation.txt` |
| VyOS legitimate transit traffic holds (0% loss) | `results/vyos-20261103-215600/30_legit_ping_h7_to_hcap.txt` |
| VyOS drops unsolicited inbound TCP/ICMP | `results/vyos-20261103-215600/40_unsolicited_tcp_hcap_to_h7.txt`, `41_unsolicited_icmp_hcap_to_h7.txt` |
| VyOS's own firewall log of the drops | `results/vyos-20261103-215600/50_vyos_firewall_log.txt` |

## Important checks before you trust a result

- **"No route to host" vs "Connection refused":** under correct default-deny
  you want *no route to host* (ARP never resolves), **not** refused —
  refused means a packet got there.
- **The ARP flood-rule bug (fixed):** earlier drafts of this PoC used a flood
  rule for ARP, which let a compromised host smuggle data inside forged ARP
  requests to every port. `flows.py`'s `arp_allow()` now installs one
  per-source ALLOW flow instead, with a catch-all ARP DENY below it. If
  `40_h4_arp_count.txt` is ever non-zero, check `20_policy_dump.txt` for a
  stray FLOOD/`NORMAL` action.
- **`fwd` must be INSTALLED, not ACTIVE**, or every pair reaches every
  other pair regardless of policy.

## Status

Open from the paper's stated scope (`main.tex`, Honest Scope paragraph):
a second router/firewall implementation (OPNsense) and a second IDS target
(Zeek) are untested; clientless access, IaC orchestration, and the
monitoring/identity planes are present in the design but not exercised by
this PoC. The Mininet cold-start timing figure remains a single,
unexplained sample; re-running it across clean-reboot trials is open work.

## License

MIT — see `LICENSE`.
