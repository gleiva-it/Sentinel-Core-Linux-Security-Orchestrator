#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;032m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

load_config() {
    local CONFIG_FILE="./sentinel.conf"
    
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else

        LOG_PATH="/var/log/secure"
        AUTH_THRESHOLD=3
        REPORT_DIR="./reports"
    fi

    mkdir -p "$REPORT_DIR"
}

load_config