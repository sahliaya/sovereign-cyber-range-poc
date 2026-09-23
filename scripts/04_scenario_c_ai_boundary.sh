#!/usr/bin/env bash
# Scenario C - Bounded-AI egress check.
# Requires Ollama installed and serving locally, with qwen2.5:1.5b already
# pulled (`ollama pull qwen2.5:1.5b`) so this run does not itself trigger a
# model download over the network, which would confound the test.
#
# Usage: ./04_scenario_c_ai_boundary.sh
set -euo pipefail

echo "--- Confirm the model server binds to loopback only ---"
ss -tln | grep 11434
# Expected: "127.0.0.1:11434", never "0.0.0.0:11434"

echo "--- Sample process-attributed sockets during inference ---"
echo "In a second terminal, run:"
echo "  watch -n 0.5 'sudo ss -tnp | grep ollama'"
echo "while this script runs the inference below."
sleep 3

/usr/bin/time -v ollama run qwen2.5:1.5b \
  "Generate a JSON adversary-action object for a network reconnaissance step, with fields: technique, target_host, expected_output."

echo
echo "Expected in the watch output throughout: every socket attributed to an"
echo "ollama process (server and client PID) shows a 127.0.0.1 peer address,"
echo "never a non-loopback one."
