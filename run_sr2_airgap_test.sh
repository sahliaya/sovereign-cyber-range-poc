#!/usr/bin/env bash
# Sovereign cyber-range PoC -- SR2 (operational autonomy) air-gap evidence run.
#
# SR2's conformance indicator (main.tex Table I): "Full deploy and exercise,
# air-gapped." Every prior sub-test ran with the host fully online. This
# script proves the opposite: with the host's own internet connection cut,
# the whole stack still deploys, operates, and recovers -- using only
# software already cached locally (ONOS's Docker image, Ollama's model),
# nothing fetched live.
#
# RUN THIS ONLY AFTER YOU HAVE PHYSICALLY DISCONNECTED THE LAPTOP (wifi off
# / cable unplugged). It will refuse to proceed if it can still reach the
# internet -- that's not a bug, that's the point: a "pass" with connectivity
# still up proves nothing about SR2.
#
# Run with sudo.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$HERE/results/sr2-airgap-$STAMP"
mkdir -p "$OUT"
ok(){ echo "[ok]  $*"; }; info(){ echo "[..]  $*"; }; warn(){ echo "[!!]  $*"; }

if [ "$EUID" -ne 0 ]; then warn "run with sudo"; exit 1; fi

echo "=== SR2 air-gap evidence run $STAMP ===" | tee "$OUT/00_summary.txt"

# ---- 0. PROVE disconnection, before and after. A "pass" here means the ----
#         rest of this run's success can't be explained by a live connection.
info "proving the host actually has no internet connectivity (expect FAILURE below)"
{
  echo "--- attempt 1: ping a public resolver ---"
  timeout 4 ping -c2 -W2 1.1.1.1 2>&1
  echo "exit=$?"
  echo "--- attempt 2: DNS resolution ---"
  timeout 4 getent hosts github.com 2>&1
  echo "exit=$?"
  echo "--- attempt 3: HTTPS fetch ---"
  timeout 4 curl -s -o /dev/null -w "http_code=%{http_code}\n" https://1.1.1.1 2>&1
} > "$OUT/01_disconnection_proof_before.txt" 2>&1
cat "$OUT/01_disconnection_proof_before.txt"

PING_FAILED=0
grep -qE "0 received|Network is unreachable|Name or service not known|unreachable" \
  "$OUT/01_disconnection_proof_before.txt" 2>/dev/null && PING_FAILED=1
CURL_FAILED=0
grep -q "http_code=000" "$OUT/01_disconnection_proof_before.txt" 2>/dev/null && CURL_FAILED=1
CURL_SUCCEEDED=0
grep -qE "http_code=(2[0-9][0-9]|3[0-9][0-9])" "$OUT/01_disconnection_proof_before.txt" 2>/dev/null && CURL_SUCCEEDED=1

if [ "$PING_FAILED" -eq 1 ] && [ "$CURL_FAILED" -eq 1 ] && [ "$CURL_SUCCEEDED" -eq 0 ]; then
  ok "confirmed offline -- proceeding"
else
  warn "this host still appears to have internet connectivity."
  warn "disconnect wifi/ethernet fully, then re-run this script."
  warn "a run started while still online cannot demonstrate SR2 -- it would"
  warn "only prove the stack works WITH internet, which was never in question."
  exit 1
fi

# ---- 1. confirm every dependency this run needs is already local, with ----
#         zero attempt to fetch anything --------------------------------------
info "confirming dependencies are cached locally (no fetch attempted)"
{
  echo "--- ONOS Docker image ---"
  docker images onosproject/onos --format "{{.Repository}}:{{.Tag}} ({{.Size}})"
  echo "--- Ollama model ---"
  # query Ollama's own REST API directly rather than the CLI -- the CLI's
  # behavior under sudo/root's HOME is unreliable (a false "MISSING" was
  # observed live even though the model is present); the API is immune to
  # that since it's a plain loopback network call, not filesystem/env based.
  curl -s http://127.0.0.1:11434/api/tags 2>/dev/null | grep -o '"name":"[^"]*qwen[^"]*"' \
    || echo "MISSING -- this run will fail at the AI-egress step"
  echo "--- mininet / openvswitch already installed ---"
  dpkg -l mininet openvswitch-switch 2>&1 | grep "^ii" || echo "MISSING"
} > "$OUT/02_cached_dependencies.txt" 2>&1
cat "$OUT/02_cached_dependencies.txt"

# ---- 2. full deploy: bring up ONOS from the LOCAL image, no pull ----------
info "bringing up ONOS from the already-cached image (docker run, no pull)"
docker rm -f onos >/dev/null 2>&1
docker run -d --name onos -p 6653:6653 -p 8181:8181 -p 8101:8101 onosproject/onos:latest \
  > "$OUT/10_onos_start.txt" 2>&1
sleep 2
cat "$OUT/10_onos_start.txt"

info "waiting for ONOS REST API (up to 90s, offline boot can be slower)"
READY=0
for i in $(seq 1 18); do
  if curl -s -o /dev/null -w '%{http_code}' -u onos:rocks http://127.0.0.1:8181/onos/v1/devices 2>/dev/null | grep -q 200; then
    READY=1; break
  fi
  sleep 5
done
if [ "$READY" -eq 1 ]; then
  ok "ONOS REST API up, offline, from local image"
else
  warn "ONOS never came up -- SR2 run fails here. See $OUT/10_onos_start.txt"
  exit 1
fi

# REST API being up does NOT mean the openflow app is active yet -- it's a
# separate Karaf bundle that activates afterward, sometimes well after the
# REST API itself responds. Every prior online run of this PoC had a long,
# human-paced gap between "ONOS is up" and "a switch actually needs it",
# which hid this. This script doesn't have that gap, so make it explicit:
# activate the app and poll for ACTIVE instead of assuming timing works out
# (two live offline runs failed exactly this way: OVS connected over TCP
# and got "Connection reset by peer" immediately -- the port was listening
# but no OpenFlow handler was behind it yet).
info "explicitly activating org.onosproject.openflow and waiting for ACTIVE (up to 60s)"
python3 - "$HERE" <<'PYEOF' > "$OUT/17_openflow_app_activate.txt" 2>&1
import sys, time
sys.path.insert(0, sys.argv[1])
from flows import Onos
o = Onos(password="rocks")
o.activate("org.onosproject.openflow")
for i in range(24):
    state = o.app_state("org.onosproject.openflow")
    print(f"t={i*2.5:.1f}s state={state}")
    if state == "ACTIVE":
        print("ACTIVATED")
        sys.exit(0)
    time.sleep(2.5)
print("NEVER BECAME ACTIVE")
sys.exit(1)
PYEOF
APP_READY=$?
cat "$OUT/17_openflow_app_activate.txt"
if [ "$APP_READY" -ne 0 ]; then
  warn "org.onosproject.openflow never reached ACTIVE -- stopping before this"
  warn "produces the same 'connection reset' failure as before."
  docker logs onos --tail 80 > "$OUT/18_onos_logs_app_activation_failure.txt" 2>&1
  exit 1
fi
ok "openflow app ACTIVE -- proceeding"

# ---- 3. full exercise: the real single-slice reproduction sequence -------
info "cleaning up any stale Mininet state from a prior session first"
mn -c > "$OUT/15_pre_cleanup.txt" 2>&1

info "bringing up the single-slice topology and running the full test suite, offline"
# topo.py --test ends in CLI(net), which blocks reading stdin until EOF or
# an explicit exit, then tears the whole network down -- backgrounding it
# with a bare '&' lets it inherit a stdin that hits EOF almost immediately
# (observed live: the network spun up and tore itself down before
# run_tests.sh ever got to use it, producing "host not found" everywhere).
# Piping an endless, empty stream into it keeps the CLI blocked forever,
# exactly like a human leaving the CLI window open without typing anything.
tail -f /dev/null | python3 "$HERE/topo.py" --test &
TOPO_PID=$!

# A fixed sleep here caused a real failure on an earlier offline run: the
# switch hadn't finished registering with ONOS yet (device available: False)
# when flows.py push ran, so the policy silently failed to install (empty
# policy dump), and h1<->h2 lost 100% of traffic under the MITM sub-test --
# a false pass, since "no packets anywhere" looks like "default-deny holds"
# unless you check the authorized pair specifically. Poll for the device
# instead of guessing a sleep duration; offline boot is slower than online.
info "waiting for the switch to register as available in ONOS (up to 60s)"
python3 - "$HERE" <<'PYEOF' > "$OUT/16_device_wait.txt" 2>&1
import sys
sys.path.insert(0, sys.argv[1])
from flows import Onos
o = Onos(password="rocks")
ok = o.all_devices_available(1, timeout=60)
print("device available:", ok)
sys.exit(0 if ok else 1)
PYEOF
DEVICE_READY=$?
cat "$OUT/16_device_wait.txt"
if [ "$DEVICE_READY" -ne 0 ]; then
  warn "switch never registered as available after 60s -- capturing diagnostics"
  warn "NOW, before any cleanup, so the evidence isn't torn down before we"
  warn "can look at it (that's exactly what happened last time)."
  {
    echo "=== ONOS container logs (last 80 lines) ==="
    docker logs onos --tail 80 2>&1
    echo
    echo "=== OVS: bridges/ports as they exist RIGHT NOW, pre-cleanup ==="
    ovs-vsctl show 2>&1
    echo
    echo "=== raw ONOS device list ==="
    curl -s -u onos:rocks http://127.0.0.1:8181/onos/v1/devices 2>&1
    echo
    echo "=== OpenFlow port 6653 reachable from the host? ==="
    timeout 3 bash -c 'cat < /dev/null > /dev/tcp/127.0.0.1/6653' && echo "REACHABLE" || echo "NOT REACHABLE"
    echo
    echo "=== is the OVS kernel module / ovs-vswitchd actually running? ==="
    systemctl is-active openvswitch-switch 2>&1
    ps aux | grep -E "ovs-vswitchd|ovsdb-server" | grep -v grep
    echo
    echo "=== mininet/topo.py process still alive? ==="
    ps aux | grep "topo.py --test" | grep -v grep
  } > "$OUT/17_failure_diagnostics.txt" 2>&1
  cat "$OUT/17_failure_diagnostics.txt"
  warn "diagnostics captured in $OUT/17_failure_diagnostics.txt -- cleaning up now"
  kill "$TOPO_PID" 2>/dev/null; pkill -f "topo.py --test" 2>/dev/null; mn -c >/dev/null 2>&1
  exit 1
fi
ok "device available -- proceeding"

python3 "$HERE/flows.py" status --password rocks > "$OUT/20_onos_status_offline.txt" 2>&1
cat "$OUT/20_onos_status_offline.txt"

ONOS_PW=rocks "$HERE/run_tests.sh" > "$OUT/30_run_tests_offline.log" 2>&1
RUN_TESTS_RC=$?
tail -30 "$OUT/30_run_tests_offline.log"
if [ "$RUN_TESTS_RC" -eq 0 ]; then
  ok "run_tests.sh completed offline (SR7, MITM, AI-egress, footprint)"
else
  warn "run_tests.sh exited non-zero offline -- see 30_run_tests_offline.log"
fi

# ---- 4. recover: tear down and confirm clean re-deploy still works -------
info "tearing down and re-deploying once more, to exercise 'recovers' not just 'deploys'"
kill "$TOPO_PID" 2>/dev/null
pkill -f "topo.py --test" 2>/dev/null
mn -c > "$OUT/40_teardown.txt" 2>&1
tail -f /dev/null | python3 "$HERE/topo.py" --test &
TOPO_PID2=$!

python3 - "$HERE" <<'PYEOF' > "$OUT/41_recover_status_offline.txt" 2>&1
import sys
sys.path.insert(0, sys.argv[1])
from flows import Onos
o = Onos(password="rocks")
ok = o.all_devices_available(1, timeout=60)
print("device available:", ok)
PYEOF
python3 "$HERE/flows.py" status --password rocks >> "$OUT/41_recover_status_offline.txt" 2>&1
cat "$OUT/41_recover_status_offline.txt"
kill "$TOPO_PID2" 2>/dev/null
pkill -f "topo.py --test" 2>/dev/null
mn -c > /dev/null 2>&1

# ---- 5. re-prove disconnection at the END, so a mid-run reconnect can't --
#         quietly explain away an earlier success ---------------------------
info "re-confirming still offline at end of run"
{
  timeout 4 ping -c2 -W2 1.1.1.1 2>&1
  echo "exit=$?"
} > "$OUT/90_disconnection_proof_after.txt" 2>&1
cat "$OUT/90_disconnection_proof_after.txt"

docker rm -f onos >/dev/null 2>&1

echo
echo "=== DONE. Evidence in: $OUT ==="
echo "Reconnect, then share this folder -- key files:"
echo "  01_disconnection_proof_before.txt / 90_*_after.txt  -- proves the air-gap was real"
echo "  02_cached_dependencies.txt   -- proves nothing was fetched live"
echo "  10_onos_start.txt            -- ONOS booted from local image, offline"
echo "  30_run_tests_offline.log     -- the full SR7/MITM/AI-egress/footprint suite, offline"
echo "  41_recover_status_offline.txt -- a second clean deploy, proving 'recovers' too"
