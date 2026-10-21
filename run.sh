#!/usr/bin/env bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

set -euo pipefail

learner_config=$SCRIPT_DIR/config/learner_args
mapper_config=$SCRIPT_DIR/config/mapperconfig.toml
MAPPER_PID=""
RST_RULE_ADDED=0

# These values have to be consistent with the arguments in config
SERVER_PORT=9000
HOST=127.0.0.1
MAPPER_PORT=18200

# Only drop RSTs that go to the server: the mapper host's kernel sends these in reply
# to SYN-ACKs aimed at the raw socket. With the SUT on localhost, the server's own RSTs
# also pass through OUTPUT, so a rule without --dport would hide them from the mapper.
RST_RULE=(OUTPUT -p tcp --dport "$SERVER_PORT" --tcp-flags RST RST -j DROP)


# Clean up background processes on exit
cleanup() {
  echo "Cleaning up..."
    if [[ -n "${MAPPER_PID:-}" ]]; then
        kill "$MAPPER_PID" 2>/dev/null || true
    fi
    if [[ "$RST_RULE_ADDED" -eq 1 ]]; then
        sudo iptables -D "${RST_RULE[@]}" 2>/dev/null || true
    fi
}
trap cleanup EXIT


start_mapper() {
    # Start TCP Mapper
    echo "Starting Mapper..."

    # Clear alerts from previous runs so the Snort log does not grow indefinitely.
    DPI_ALERT_FILE="/var/log/snort/alert_fast.txt"

    if [[ -f "$DPI_ALERT_FILE" ]]; then
        sudo truncate -s 0 "$DPI_ALERT_FILE"
        echo "Cleared previous Snort alerts file."
    fi

    if sudo iptables -C "${RST_RULE[@]}" 2>/dev/null; then
        RST_RULE_ADDED=0
    else
        sudo iptables -A "${RST_RULE[@]}"
        RST_RULE_ADDED=1
    fi

    (
        source "$SCRIPT_DIR/mapper/.venv/bin/activate"
        echo sudo "$SCRIPT_DIR/mapper/.venv/bin/python" "$SCRIPT_DIR/mapper/main.py" "$mapper_config"
        sudo "$SCRIPT_DIR/mapper/.venv/bin/python" "$SCRIPT_DIR/mapper/main.py" "$mapper_config"
    ) &

    MAPPER_PID=$!
    # Wait for mapper to be ready
    echo "Wait for mapper to be ready"
    until ss -ltn sport = :$MAPPER_PORT | grep -q LISTEN; do
        sleep 0.1
    done
    echo "Mapper started (PID $MAPPER_PID)"
    sleep 1
}

start_learner() {
    # Start learner
    echo "Starting Learner..."
    echo java -jar "$SCRIPT_DIR/learner/target/TCP-Learner.jar" "$learner_config" "$@"
    java -jar "$SCRIPT_DIR/learner/target/TCP-Learner.jar" "$learner_config" "$@"
}

while [[ $# -gt 0 && "$1" =~ ^- ]]; do case $1 in
    -lc | --learner-config )
        [[ $# -ge 2 ]] || { echo "Missing value for $1"; exit 1; }
        shift;
        learner_config=$1
        ;;
    -mc | --mapper-config )
        [[ $# -ge 2 ]] || { echo "Missing value for $1"; exit 1; }
        shift;
        mapper_config=$1
        ;;
    * )
        break
        ;;
    esac; shift; done

start_mapper
start_learner "$@"