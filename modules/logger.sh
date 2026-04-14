check_suspicius_logs() {
    # 1. Preparacion de variables desde la configuración
    # Si LOG_PATH está vacío en el .conf, usamos un fallback seguro
    local target_log="${LOG_PATH:-/var/log/auth.log}"
    local threshold="${AUTH_THRESHOLD:-5}"
    
    # Verificacion de lectura
    if [[ ! -r "$target_log" ]]; then
        log_event "WARN" "No se puede leer el log" "$target_log (¿Permisos de root?)"
        return 1
    fi

    log_event "INFO" "Analizando intentos de acceso..." "$target_log"

    # 2. Analisis de intentos fallidos
    local PATRON="Failed password|Invalid user"
    local FALLIDOS=$(egrep -c "$PATRON" "$target_log" 2>/dev/null)
    
    # Regex para extraccion de datos
    local REGEX_IP='\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    local REGEX_INJECTION='(\\x1b\[[0-9;]*[mK]|<script.*>|%3Cscript.*%3E|(\.\.\/|\.\.\\){2,})'

    # 3. Lógica de Alertas de Acceso
    if [ "$FALLIDOS" -gt 0 ]; then
        local nivel="WARN"
        [ "$FALLIDOS" -gt "$threshold" ] && nivel="CRITIC"
        
        log_event "$nivel" "Eventos sospechosos detectados" "$FALLIDOS"

        if [ "$JSON_MODE" = false ]; then
            # Reporte visual
            echo -e "${YELLOW}[*] Top 5 IPs atacantes:${NC}"
            grep -Po "$REGEX_IP" "$target_log" | sort | uniq -c | sort -nr | head -5
            
            echo -e "${YELLOW}[*] Top 5 Usuarios más buscados:${NC}"
            egrep "$PATRON" "$target_log" | grep -Po '[^ ]+(?= from)' | sort | uniq -c | sort -nr | head -5
        else

            local top_ips=$(grep -Po "$REGEX_IP" "$target_log" | sort | uniq -c | sort -nr | head -3 | tr '\n' ',' | sed 's/,$//')
            log_event "DATA" "Top IPs detectadas" "$top_ips"
        fi
    else
        log_event "OK" "No se detectaron anomalías en los accesos" "0"
    fi

    # 4. Analisis de Inyeccion y Manipulacion
    local INJECTION_COUNT=$(grep -aoPi "$REGEX_INJECTION" "$target_log" | wc -l)

    if [ "$INJECTION_COUNT" -gt 0 ]; then
        log_event "CRITIC" "Intentos de inyección detectados" "$INJECTION_COUNT"
        
        if [ "$JSON_MODE" = false ]; then
            echo -e "${RED}[!] Detalles de la inyección (cat -v):${NC}"
            grep -aPi "$REGEX_INJECTION" "$target_log" | head -n 5 | cat -v
        fi
    else
        log_event "OK" "Integridad de logs verificada (No inyección)" "0"
    fi
}