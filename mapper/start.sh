#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
python3 $SCRIPT_DIR/main.py $SCRIPT_DIR/../config/mapperconfig.toml
