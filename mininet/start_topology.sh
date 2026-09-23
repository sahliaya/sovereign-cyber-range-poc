#!/usr/bin/env bash
# Starts the 4-host PoC topology under ONOS (interactive Mininet CLI).
# Requires: Mininet, Open vSwitch, and an ONOS controller already running
# and reachable at 127.0.0.1:6653 (see ../onos/ for how to bring ONOS up).
#
# Usage: sudo ./start_topology.sh
set -euo pipefail

sudo mn -c

sudo mn --topo single,4 \
  --controller=remote,ip=127.0.0.1,port=6653 \
  --switch ovsk,protocols=OpenFlow13 \
  --mac
