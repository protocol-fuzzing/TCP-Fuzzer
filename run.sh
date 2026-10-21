#!/usr/bin/env bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

set -euo pipefail

learner_config=$SCRIPT_DIR/config/learner_args
mapper_config=$SCRIPT_DIR/config/mapperconfig.toml
MAPPER_PID_DIR=""
RST_RULE_ADDED=0

# These values have to be consistent with the arguments in config
SERVER_PORT=9000
HOST=127.0.0.1
MAPPER_PORT=18200

# Only drop RSTs that go to the server: the mapper host's kernel sends these in reply
# to SYN-ACKs aimed at the raw socket. With the SUT on localhost, the server's own RSTs
# also pass through OUTPUT, so a rule without --dport would hide them from the mapper.
RST_RULE=(OUTPUT -p tcp --dport "$SERVER_PORT" --tcp-flags RST RST -j DROP)


# The mapper runs as root, so only sudo can stop it. Ask it to stop with
# SIGINT (Ctrl-C) first, and force it with SIGKILL after 5 s.
stop_mapper() {
    local pid
    [[ -r "$MAPPER_PID_DIR/mapper.pid" ]] || return 0
    read -r pid < "$MAPPER_PID_DIR/mapper.pid" || return 0
    [[ "$pid" =~ ^[0-9]+$ ]] || return 0
    ps -p "$pid" >/dev/null || return 0
    sudo kill -INT "$pid" 2>/dev/null || true
    for _ in $(seq 50); do
        ps -p "$pid" >/dev/null || return 0
        sleep 0.1
    done
    echo "Mapper (PID $pid) did not stop, killing it"
    sudo kill -KILL "$pid" 2>/dev/null || true
}

# Clean up background processes on exit
cleanup() {
  echo "Cleaning up..."
    if [[ -n "${MAPPER_PID_DIR:-}" ]]; then
        stop_mapper
        rm -rf "$MAPPER_PID_DIR"
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

    # Write the root shell PID (not sudo's), then exec the mapper.
    # Use a temp dir we own to avoid /tmp fs.protected_regular=2 issues.
    MAPPER_PID_DIR="$(mktemp -d)"
    echo sudo "$SCRIPT_DIR/mapper/.venv/bin/python" "$SCRIPT_DIR/mapper/main.py" "$mapper_config"
    sudo sh -c 'pid_file=$1; shift; printf "%s\n" "$$" > "$pid_file"; exec "$@"' \
        sh "$MAPPER_PID_DIR/mapper.pid" \
        "$SCRIPT_DIR/mapper/.venv/bin/python" "$SCRIPT_DIR/mapper/main.py" "$mapper_config" &

    # Wait for mapper to be ready
    echo "Wait for mapper to be ready"
    until ss -ltn sport = :$MAPPER_PORT | grep -q LISTEN; do
        sleep 0.1
    done
    echo "Mapper started (PID $(cat "$MAPPER_PID_DIR/mapper.pid"))"
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