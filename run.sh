#!/usr/bin/env bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

set -euo pipefail

learner_config=$SCRIPT_DIR/config/learner_args
mapper_config=$SCRIPT_DIR/config/mapperconfig.toml
MAPPER_PID=""

# These values have to be consistent with the arguments in config
#SERVER_PORT=9000
HOST=127.0.0.1
MAPPER_PORT=18200


# Clean up background processes on exit
cleanup() {
  echo "Cleaning up..."
    if [[ -n "${MAPPER_PID:-}" ]]; then
        kill "$MAPPER_PID" 2>/dev/null || true
    fi
  sudo iptables --flush OUTPUT
}
trap cleanup EXIT

start_mapper() {
    # Start TCP Mapper
    echo "Starting Mapper..."
    (
        sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
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