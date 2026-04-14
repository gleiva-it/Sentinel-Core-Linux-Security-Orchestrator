# modules/scanner.sh
audit_permissions(){
    # Usamos la ruta de reportes del .conf o una por defecto
    local REPORTE="${REPORT_DIR:-./reports}/audit_$(date +%Y%m%d_%H%M).log"
    local CONTADOR=0
    
    # Si no estamos en modo JSON, mostramos un encabezado estético
    if [ "$JSON_MODE" = false ]; then
        echo -e "${YELLOW}--- INICIANDO AUDITORÍA DE SEGURIDAD ---${NC}"
    fi

    # --- 1. ANALIZANDO SUID/SGID ---
    # Usamos la PERM_WHITELIST definida en el .conf
    while IFS= read -r binario; do
        if [[ ! " $PERM_WHITELIST " =~ " $binario " ]]; then
            local owner=$(stat -c '%U' "$binario" 2>/dev/null)
            log_event "WARN" "Binario SUID no reconocido" "$binario (Owner: $owner)"
            ((CONTADOR++))
        fi
    done < <(find /usr/bin /usr/sbin /bin -perm /6000 -type f 2>/dev/null)

    # --- 2. ARCHIVOS DE CONFIGURACIÓN WORLD-WRITABLE ---
    local EXTENSIONES='.*(\.conf|\.env|\.key|\.php|\.bak|config.*)'
    while IFS= read -r cfg; do
        log_event "WARN" "Permisos inseguros (World-Writable)" "$cfg"
        ((CONTADOR++))
    done < <(find $AUDIT_PATHS -type f -regextype posix-extended -iregex "$EXTENSIONES" -perm -0002 2>/dev/null)

    # --- 3. ESCANEO DE SECRETOS (Zero Trust) ---
    local REGEX_SECRETS='(AKIA[0-9A-Z]{16}|BEGIN.*PRIVATE|password|passwd|secret|token|auth_key)[[:space:]]*[:=]*[[:space:]]*[^[:space:]]+'
    
    # Buscamos en archivos que tengan permisos de lectura para todos
    while IFS= read -r archivo_expuesto; do
        local fuga=$(egrep -io "$REGEX_SECRETS" "$archivo_expuesto" 2>/dev/null)
        if [ -n "$fuga" ]; then
            log_event "CRITIC" "Secreto expuesto en archivo público" "$archivo_expuesto (Patrón: ${fuga:0:15}...)"
            ((CONTADOR++))
        fi
    done < <(find $AUDIT_PATHS -type f -perm -0002 2>/dev/null)

    # --- RESUMEN FINAL ---
    if [ "$CONTADOR" -eq 0 ]; then
        log_event "INFO" "Auditoría completada: No se hallaron riesgos." "0"
    else
        log_event "WARN" "Auditoría completada: Riesgos totales hallados" "$CONTADOR"
    fi

    # Guardar reporte (solo si no estamos en modo JSON para no ensuciar el pipe)
    if [ "$JSON_MODE" = false ]; then
        echo "Reporte generado en: $REPORTE"
    fi
}
