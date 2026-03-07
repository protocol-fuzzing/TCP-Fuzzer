#!/bin/bash
# start_server.sh
#
# Wrapper script that restarts serverAdapter.py after every client connection.
#
# WHY: serverAdapter.py now exits after serving one client (one learning query).
# This ensures the Mac OS TCP stack is fully reset between queries, eliminating
# the non-determinism caused by lingering TIME_WAIT and half-open connections.
#
# Usage:
#   ./start_server.sh                          # use defaults (0.0.0.0:9000)
#   ./start_server.sh --port 9000              # custom port
#   ./start_server.sh --host 0.0.0.0 --port 9000
#

# All arguments are passed directly to serverAdapter.py
# Usage: ./start_server.sh --host 0.0.0.0 --port 9000
EXTRA_ARGS="$@"

echo "[*] Auto-restart server wrapper started. Args: $EXTRA_ARGS"
echo "[*] Press Ctrl+C to stop."

while true; do
    python3 serverAdapter.py $EXTRA_ARGS
    EXIT_CODE=$?

    # Exit the loop on:
    #   1   → Ctrl+C caught by Python's signal handler (sys.exit(1))
    #   130 → Ctrl+C killed the process at shell level (SIGINT)
    #   143 → SIGTERM (e.g. kill command)
    if [ $EXIT_CODE -eq 1 ] || [ $EXIT_CODE -eq 130 ] || [ $EXIT_CODE -eq 143 ]; then
        echo "[*] Wrapper received stop signal, exiting."
        break
    fi

    echo "[*] Server exited (code $EXIT_CODE), restarting for next query..."
    sleep 0.2   # give the OS time to release the port before the next process binds it
done
