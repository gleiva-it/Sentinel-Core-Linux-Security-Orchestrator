#!/bin/bash

# 1. Cargar módulos (Importación)
source ./lib/globals.sh
source ./modules/utils.sh
source ./modules/logger.sh
source ./modules/scanner.sh
source ./modules/monitor.sh

# 2. Verificación de privilegios
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: Ejecutar como root.${NC}"
   exit 1
fi


JSON_MODE=false

# Detectar flag --json
if [[ "$1" == "--json" ]]; then
    JSON_MODE=true
fi

# 3. Main Menu
while true; do
    clear
    echo -e "${YELLOW}=== SENTINEL: SECURITY AUDIT TOOL ===${NC}"
    generate_sys_id  
    
    echo -e "1) SCAN LOGS"
    echo "2) PERMISSION AUDIT"
    echo "3) MONITOR PROCESSES"
    echo "4) EXIT"
    
    read -p "Option [1-4]: " option

    case $option in
        1) check_suspicius_logs ;;
        2) audit_permissions ;;
        3) monitor_processes ;;
        4) exit 0 ;;
        *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
    
    echo -e "${YELLOW}--- Presione [ENTER] para volver ---${NC}"
    read
done