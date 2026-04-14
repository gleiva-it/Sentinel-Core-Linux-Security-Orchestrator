#!/bin/bash

generate_sys_id() {
    local ID_SOURCE="/etc/machine-id"
    if [[ -f "$ID_SOURCE" ]]; then
        SYS_ID=$(sha256sum "$ID_SOURCE" | cut -c 1-8 )
    else 
        SYS_ID=$(hostname | sha256sum | cut -c 1-8 )
    fi
    echo -e "${YELLOW}[*] Sentinel Bash ID: $SYS_ID${NC}"
}