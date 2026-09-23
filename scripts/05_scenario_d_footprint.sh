#!/usr/bin/env bash
# Scenario D - Footprint measurement.
# Two parts: (1) steady-state resource usage of the already-running stack,
# and (2) a separate cold-start timing run. Run part 2 on a clean
# `sudo mn -c` state, ideally after a fresh reboot, to get a clean sample
# (the 125.65s figure reported in the paper was flagged as unexplained and
# not yet reproduced across repeated trials -- treat any single sample the
# same way).
set -euo pipefail

echo "=== Part 1: steady-state footprint (run while the topology is up) ==="
free -h
nproc
uptime
docker stats onos --no-stream

echo
echo "=== Part 2: cold-start timing (run on a clean state) ==="
echo "This will tear down any existing Mininet topology. Ctrl-C to abort."
sleep 3
time (sudo mn -c; sudo mn --topo single,4 \
  --controller=remote,ip=127.0.0.1,port=6653 \
  --switch ovsk,protocols=OpenFlow13 --test pingall)
