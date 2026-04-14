generate_sys_id() {
	local ID_SOURCE="/etc/machine-id"

	if [[ -f "$ID_SOURCE" ]]; then

		SYS_ID=$(sha256sum "$ID_SOURCE" | cut -c 1-8 )
	else 

		SYS_ID=$(hostname | sha256sum | cut -c 1-8 )

	fi

	echo -e "${YELLOW}[*] Sentinel Bash ID: $SYS_ID${NC}"
}

# $1: Nivel (INFO, WARN, CRITIC)
# $2: Mensaje
# $3: Valor (para el JSON)
log_event() {
    local level=$1
    local msg=$2
    local value=$3

    if [ "$JSON_MODE" = true ]; then
        # Generamos una línea JSON usando jq
        jq -n --arg lv "$level" --arg msg "$msg" --arg val "$value" \
           '{timestamp: (now | strflocaltime("%Y-%m-%dT%H:%M:%S")), level: $lv, message: $msg, data: $val}'
    else
        # Salida normal con colores
        case $level in
            "CRITIC") echo -e "${RED}[!!!] $msg: $value${NC}" ;;
            "WARN")   echo -e "${YELLOW}[!] $msg: $value${NC}" ;;
            *)        echo -e "${GREEN}[+] $msg${NC}" ;;
        esac
    fi
}