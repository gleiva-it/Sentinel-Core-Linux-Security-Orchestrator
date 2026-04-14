#!/bin/bash

monitor_processes() {
    # (Bash Parameter Expansion)
    local rutas_busqueda="${RUTAS_CRITICAS:-/tmp|/dev/shm|/var/tmp}"
    local limite_cpu="${TOP_PROCESS_LIMIT:-10}"
    
    # Temporales FIles
    local tmp_amenazas=$(mktemp)
    local tmp_normales=$(mktemp)

    # Solo mostramos headers si NO estamos en modo JSON
    if [ "$JSON_MODE" = false ]; then
        echo -e "${YELLOW}--- MONITOR DE PROCESOS (Rutas: $rutas_busqueda) ---${NC}"
        echo -e "${GREEN}Escaneando sistema...${NC}"
    fi

    # 2. Analisis del colector de procesos
    ps -eo user:10,pid,pcpu,pmem,stat,args --sort=-pcpu | while read -r user pid cpu mem stat args; do
        # Saltar el encabezado de ps
        [[ "$user" == "USER" ]] && continue

        local alerta_tags=""
        local es_amenaza=false
        local motivo_amenaza=""

        # Detección 1: Ejecucion en rutas criticas
        if [[ "$args" =~ $rutas_busqueda ]]; then
            alerta_tags+="RUTA_SOSPECHOSA "
            motivo_amenaza="Ejecución en área de escritura temporal"
            es_amenaza=true
        fi
    
        # Detección 2: Fileless Malware (Uso de /proc)
        local exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
        if [[ -n "$exe_path" && ! -f "$exe_path" ]]; then
            alerta_tags+="FILELESS "
            motivo_amenaza="Binario eliminado en disco (Fileless)"
            es_amenaza=true
        fi

        if [ "$es_amenaza" = true ]; then
            if [ "$JSON_MODE" = true ]; then
                # Si es JSON, disparamos el evento al log estructurado
                log_event "CRITICAL" "Proceso sospechoso detectado" "{\"pid\": \"$pid\", \"user\": \"$user\", \"cause\": \"$motivo_amenaza\", \"cmd\": \"$args\"}"
            else
                # Formato visual para humanos
                printf "%-10s %-7s %-5s %-5s %-15s %-30s ${RED}[%s]${NC}\n" \
                    "$user" "$pid" "$cpu" "$mem" "$stat" "${args:0:30}" "$alerta_tags" >> "$tmp_amenazas"
            fi
        else
            # Si no es amenaza, lo mandamos a la lista normal (solo si no es modo JSON)
            if [ "$JSON_MODE" = false ]; then
                printf "%-10s %-7s %-5s %-5s %-15s %-30s\n" \
                    "$user" "$pid" "$cpu" "$mem" "$stat" "${args:0:30}" >> "$tmp_normales"
            fi
        fi
    done

    # 4. Presentacion de resultados
    if [ "$JSON_MODE" = false ]; then
        echo -e "--------------------------------------------------------------------------------"
        printf "%-10s %-7s %-5s %-5s %-15s %-30s %s\n" "USUARIO" "PID" "%CPU" "%MEM" "ESTADO" "COMANDO" "ALERTAS"
        echo -e "--------------------------------------------------------------------------------"

        if [ -s "$tmp_amenazas" ]; then
            echo -e "${RED}>>> AMENAZAS DETECTADAS <<<${NC}"
            cat "$tmp_amenazas"
            echo -e "--------------------------------------------------------------------------------"
        fi

        echo -e "${GREEN}>>> Top $limite_cpu Procesos del Sistema <<<${NC}"
        head -n "$limite_cpu" "$tmp_normales"

        # 5. Interactividad
        echo -e "\n${YELLOW}[?] Ingrese PID para análisis profundo o 'n' para salir:${NC}"
        read pid_gestion

        if [[ "$pid_gestion" =~ ^[0-9]+$ ]] && ps -p "$pid_gestion" > /dev/null; then
            analisis_profundo_pid "$pid_gestion"
        fi
    fi

    # Limpieza
    rm "$tmp_amenazas" "$tmp_normales"
}

analisis_profundo_pid() {
    local pid=$1
    echo -e "\n${GREEN}>>> ANÁLISIS DEL PID $pid <<<${NC}"
    
    local ppid=$(ps -p "$pid" -o ppid= | tr -d ' ')
    local comm_padre=$(ps -p "$ppid" -o comm= 2>/dev/null || echo "Desconocido")
    
    echo -e "${YELLOW}Padre del proceso (PPID):${NC} $ppid ($comm_padre)"
    
    echo -e "${YELLOW}Conexiones de red activas:${NC}"
    if command -v ss > /dev/null; then
        ss -antp | grep "pid=$pid," || echo "Sin conexiones activas."
    fi

    echo -e "\nAcciones de respuesta: 1)SIGSTOP 2)SIGTERM 3)SIGKILL 4)Salir"
    read -p "Opción: " sig_opcion
    case $sig_opcion in
        1) kill -19 "$pid" && echo "Suspendido." ;;
        2) kill -15 "$pid" && echo "Terminado." ;;
        3) kill -9 "$pid"  && echo "Aniquilado." ;;
    esac
}