#!/usr/bin/env bash
# SR7 default-deny policy: with ONOS's reactive-forwarding app deactivated
# (see step 0 below), nothing is reachable except through the explicit
# ALLOW flows installed here for the one authorized pair, h1 <-> h2.
#
# Run this from a normal shell (not the mininet CLI), after start_topology.sh
# has brought up the switch and it has connected to ONOS.
#
# Usage: ./01_install_default_deny_flows.sh [device-id]
set -euo pipefail

ONOS_USER=onos
ONOS_PASS=rocks
ONOS_URL=http://127.0.0.1:8181/onos/v1
DEV="${1:-of:0000000000000001}"

echo "--- 0. Deactivate reactive forwarding (default-deny baseline) ---"
curl -u "$ONOS_USER:$ONOS_PASS" -X DELETE \
  "$ONOS_URL/applications/org.onosproject.fwd/active"

echo "--- 1. ARP flood rule (resolution only, not data forwarding) ---"
curl -u "$ONOS_USER:$ONOS_PASS" -X POST "$ONOS_URL/flows/$DEV" \
  -H 'Content-Type: application/json' -d '{
  "priority": 50000, "isPermanent": true, "deviceId": "'"$DEV"'",
  "treatment": {"instructions":[{"type":"OUTPUT","port":"FLOOD"}]},
  "selector": {"criteria":[{"type":"ETH_TYPE","ethType":"0x0806"}]}
}'

echo "--- 2. h1 -> h2 ALLOW flow, MAC-rewritten (ARP-hardened) ---"
curl -u "$ONOS_USER:$ONOS_PASS" -X POST "$ONOS_URL/flows/$DEV" \
  -H 'Content-Type: application/json' -d '{
  "priority": 45000, "isPermanent": true, "deviceId": "'"$DEV"'",
  "treatment": {"instructions":[
    {"type":"L2MODIFICATION","subtype":"ETH_DST","mac":"00:00:00:00:00:02"},
    {"type":"L2MODIFICATION","subtype":"ETH_SRC","mac":"00:00:00:00:00:01"},
    {"type":"OUTPUT","port":"2"}
  ]},
  "selector": {"criteria":[
    {"type":"ETH_TYPE","ethType":"0x0800"},
    {"type":"IPV4_SRC","ip":"10.0.0.1/32"},
    {"type":"IPV4_DST","ip":"10.0.0.2/32"}
  ]}
}'

echo "--- 3. h2 -> h1 ALLOW flow, MAC-rewritten (return path) ---"
curl -u "$ONOS_USER:$ONOS_PASS" -X POST "$ONOS_URL/flows/$DEV" \
  -H 'Content-Type: application/json' -d '{
  "priority": 45000, "isPermanent": true, "deviceId": "'"$DEV"'",
  "treatment": {"instructions":[
    {"type":"L2MODIFICATION","subtype":"ETH_DST","mac":"00:00:00:00:00:01"},
    {"type":"L2MODIFICATION","subtype":"ETH_SRC","mac":"00:00:00:00:00:02"},
    {"type":"OUTPUT","port":"1"}
  ]},
  "selector": {"criteria":[
    {"type":"ETH_TYPE","ethType":"0x0800"},
    {"type":"IPV4_SRC","ip":"10.0.0.2/32"},
    {"type":"IPV4_DST","ip":"10.0.0.1/32"}
  ]}
}'

echo "--- Verify: h4 should have NO matching flow in either direction ---"
curl -s -u "$ONOS_USER:$ONOS_PASS" "$ONOS_URL/flows/$DEV" | python3 -m json.tool
