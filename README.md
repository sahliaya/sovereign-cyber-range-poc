# Sovereign SDN/NFV Cyber Range — PoC Reproduction Scripts

Reproduction material for the proof-of-concept reported in *A Sovereign,
SDN/NFV-Based Cyber Range: A Reference Architecture and Feasibility
Proof-of-Concept* (Section V). Everything here runs on a single commodity
laptop with Mininet, Open vSwitch, and ONOS — no cloud, no external service.

## Requirements

- Mininet + Open vSwitch (`sudo apt install mininet`)
- Docker (to run ONOS)
- `arpspoof` (dsniff package), `tcpdump`, `nc`
- [Ollama](https://ollama.com) with `qwen2.5:1.5b` pulled, for Scenario C

## Layout

```
onos/                                    ONOS controller setup
mininet/start_topology.sh                4-host topology (h1-h4) under ONOS
scripts/01_install_default_deny_flows.sh SR7 default-deny + ALLOW flow install
scripts/02_scenario_a_sr7_exfiltration.txt   Baseline deny + exfiltration test
scripts/03_scenario_b_arp_hardened.txt       ARP-poisoning resistance test
scripts/04_scenario_c_ai_boundary.sh         Bounded-AI egress check
scripts/05_scenario_d_footprint.sh           Resource + cold-start footprint
```

`.sh` files are non-interactive and can be run directly. `.txt` files are
step-by-step commands meant to be run inside the interactive Mininet CLI
(`mininet>` prompt) or a Mininet host's `xterm`, since those scenarios
involve multiple concurrent processes (background captures, poisoning) that
don't reduce cleanly to a single script.

## Reproduction order

1. Bring up ONOS (`onos/README.md`).
2. `sudo ./mininet/start_topology.sh` — leave the `mininet>` CLI open.
3. In a second terminal: `./scripts/01_install_default_deny_flows.sh`.
4. Back in the Mininet CLI: follow `scripts/02_scenario_a_sr7_exfiltration.txt`.
5. Follow `scripts/03_scenario_b_arp_hardened.txt`.
6. `./scripts/04_scenario_c_ai_boundary.sh`.
7. `./scripts/05_scenario_d_footprint.sh`.

## Status

The topology (4-host, single-switch), the SR7 default-deny/exfiltration
result, and the ARP-hardened resistance result are reproduced as reported in
the paper. The Scenario D cold-start timing figure is flagged in the paper
as a single, unexplained sample — re-running it across multiple clean-reboot
trials is open work.

## License

MIT — see `LICENSE`.
