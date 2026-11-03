# Sovereign SDN/NFV Cyber Range — PoC Reproduction Scripts

Reproduction material for the proof-of-concept reported in *Toward a
Sovereign SDN/NFV Cyber Range: A Reference Architecture and Feasibility
Proof-of-Concept* (Section V, `main.tex`). Everything here runs on a single
commodity laptop with Mininet, Open vSwitch, and ONOS — no cloud, no
external service except the one-time Ollama install (do that before
air-gapping).

This repository is the reference implementation for every Section V
sub-test, including the four closed since the first CommNet'26 review
round: real NFV (Suricata), a hardened ARP policy with no flood rule,
AI-egress enforcement at the network layer, and concurrent multi-slice
isolation. If a number appears in the paper, it was produced by a script
in this repository, and the exact output is in `results/`.

## Requirements

```bash
sudo apt install mininet openvswitch-switch python3-scapy tcpdump netcat-openbsd suricata
curl -fsSL https://ollama.com/install.sh | sh   # needs internet; do before air-gapping
ollama pull qwen2.5:1.5b
```

Docker, to run ONOS (`onos/README.md`).

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
results/20261102-194225/       Reference single-slice evidence run (incl. suricata/)
results/multislice-20261103-113000/   Reference 4-slice concurrent evidence run
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
routers/firewalls (VyOS, OPNsense) and a second IDS target (Zeek) are
untested; clientless access, IaC orchestration, and the monitoring/identity
planes are present in the design but not exercised by this PoC. The
Mininet cold-start timing figure remains a single, unexplained sample;
re-running it across clean-reboot trials is open work.

## License

MIT — see `LICENSE`.
