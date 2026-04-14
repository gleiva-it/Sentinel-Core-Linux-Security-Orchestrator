#!/bin/bash

#COLOURS FOR ANALYSIS
RED='\033[0;31m'
GREEN='\033[0;032m'
YELLOW='\033[1;33m'
NC='\033[0m' #NO COLOR

#GENERATE UNIQ ID FOR A SYSTEM(FINGERPRINTING)

generate_sys_id() {
	local ID_SOURCE="/etc/machine-id"

	if [[ -f "$ID_SOURCE" ]]; then

		SYS_ID=$(sha256sum "$ID_SOURCE" | cut -c 1-8 )
	else 

		SYS_ID=$(hostname | sha256sum | cut -c 1-8 )

	fi

	echo -e "${YELLOW}[*] Sentinel Bash ID: $SYS_ID${NC}"
}
#AUDITORIUM MODULES

check_suspicius_logs(){
    echo -e "${GREEN}[+] Analizando intentos de acceso sospechosos...${NC}"

    local LOG_FILE=""
	if [[ -f "/var/log/auth.log" ]]; then
	    LOG_FILE="/var/log/auth.log"  
	elif [[ -f "/var/log/secure" ]]; then 
	    LOG_FILE="/var/log/secure" 
	fi
	 echo -e "${GREEN} log file correct read"



    if [[ -z "$LOG_FILE" ]] || [[ ! -r  "$LOG_FILE"  ]]; then
        echo -e "${YELLOW}[!] Permisos insuficientes para leer $LOG_FILE. Prueba con sudo.${NC}"
        return 1
    fi


 
    # Buscamos fallos de contraseña E intentos con usuarios inexistentes
    local PATRON="Failed password|Invalid user"
    local FALLIDOS=$(egrep -c "$PATRON" "$LOG_FILE")

    #REGEX !WARNING

    local REGEX_IP='\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'



    
    local REGEX_INJECTION='(\\x1b\[[0-9;]*[mK]|<script.*>|%3Cscript.*%3E|(\.\.\/|\.\.\\){2,})' 

    if [ "$FALLIDOS" -gt 0 ]; then
        echo -e "${RED}[ALERTA] Se detectaron $FALLIDOS eventos sospechosos en $LOG_FILE${NC}"
	        
        echo -e "${YELLOW}[*] Top 5 IPs con más intentos fallidos:${NC}"
	
	
	grep -Po "$REGEX_IP" "$LOG_FILE" | sort | uniq -c |sort -nr | head -5

	echo -e "${YELLOW}+ Top 5 usuarios mas atacados:${NC}"

	egrep "$PATRON" "$LOG_FILE" | grep -Po '[^ ]+(?= from)' | sort | uniq -c | sort -nr | head -5


	echo -e "${YELLOW}+ Usuarios invalidos:${NC}"

	sed -nE "/$PATRON/ s/.*user ([^ ]+) from.*/\1/p" "$LOG_FILE" | sort | uniq -c | sort -nr | head -n 5	
        	

    else

        echo -e "${GREEN}[OK] No se detectaron anomalías en los accesos.${NC}"
    fi
    
    echo -e "${GREEN} Buscando intentos de inyeccion y manipulacion de terminal.. ${NC}"
    

    local INJECTION=$(grep -aoPi "$REGEX_INJECTION" "$LOG_FILE" | wc -l ) 

    if [ "$INJECTION" -gt 0 ]; then
        echo -e "${RED}[CRÍTICO] Se detectaron $INJECTION intentos de inyección en los logs!${NC}"
        grep -aPi "$REGEX_INJECTION" "$LOG_FILE" | cat -v #clave cat -v
    else
        echo -e "${GREEN}[OK] No se detectó manipulación de logs.${NC}"
    fi
}


audit_permissions(){
    local REPORTE="audit_permisos_$(date +%Y%m%d_%H%M).log"
    local CONTADOR=0
    local WHITELIST="/usr/bin/passwd /usr/bin/sudo /usr/bin/chsh /usr/bin/mount /usr/bin/umount /usr/bin/su /usr/bin/gpasswd /usr/bin/chfn /usr/bin/pkexec"


    echo -e "${YELLOW}--- INICIANDO AUDITORÍA PRO ---${NC}"

    {
        echo "=========================================================="
        echo "   SENTINEL-BASH: REPORTE DE INTEGRIDAD Y PERMISOS "
        echo "=========================================================="

	
        echo -e "[!] ANALIZANDO BINARIOS CON EL BIT SUID/SGID ACTIVADO"
        
	#
        while IFS= read -r binario; do #internal field separator

		if [[ $WHITELIST =~ "$binario" ]]; then
			continue
		fi
		local owner=$(stat -c '%U' "$binario") 

		echo "HALLAZGO: ALERTA(SUID): Propietario: $owner | ruta: $binario"
                ((CONTADOR++))

	done < <(find /usr/bin /usr/sbin /bin -perm /6000 -type f 2>/dev/null ) 

	
        echo -e "\n[!] ANALIZANDO PERMISOS EN ARCHIVOS DE CONFIGURACION"
	local EXTENSIONES='.*(\.conf|\.env|\.key|\.php|\.bak|config.*)'
	
	while IFS= read -r cfg; do
		echo " [RISK] World-Writable detectado en: $cfg"
		((CONTADOR++))
	done < <(find /etc /home /var/www -type f -regextype posix-extended -iregex "$EXTENSIONES" -perm -0002 2>/dev/null)
	
	echo -e "[+] escaneando secretos en archivos inseguros"
	local REGEX_SECRETS='(AKIA[0-9A-Z]{16}|BEGIN.*PRIVATE|password|passwd|secret|token|auth_key)[[:space:]]*[:=]*[[:space:]]*[^[:space:]]+'
	while IFS= read -r archivo_777; do
		local fuga=$(egrep -io "$REGEX_SECRETS" "$archivo_777" 2>/dev/null)
		if [ -n "$fuga" ]; then
			echo " [CRITICO] Datos sensible en $archivo_777"
			echo "                      patron:$fuga"
			((CONTADOR++))
		fi
	done < <(find /etc /home /var/www -type f -perm -0002 2>/dev/null) # notar como usamos -0002 No busco 777
	# Zero trust

	if [ "$CONTADOR" -eq 0 ]; then
        	echo -e "${GREEN} SIN ERRORES"
       	else
                echo -e "${RED} Riesgos Totales $CONTADOR${NC}"
	
        fi

    } | tee "$REPORTE"   
}

monitor_processes(){
	echo -e "${YELLOW}--- MONITOR DE PROCESOS Y CAZA DE AMENAZAS (LIVE) ---${NC}"
    	local RUTAS_CRITICAS="/tmp|/dev/shm|/var/tmp"
    
	local tmp_amenazas=$(mktemp)
	local tmp_normales=$(mktemp)

	echo -e "${GREEN}Escaneando sistema completo en busca de anomalías...${NC}"

	ps -eo user:10,pid,pcpu,pmem,stat,args --sort=-pcpu | while read -r user pid cpu mem stat args; do
		local ALERTA=""
        	local ES_AMENAZA=false
        

        if [[ "$args" =~ $RUTAS_CRITICAS ]]; then
            ALERTA+="${RED}[!] RUTA ${NC}"
            ES_AMENAZA=true
        fi
	
        # 2. Detección Fileless
        local exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
        if [[ -n "$exe_path" && ! -f "$exe_path" ]]; then
            ALERTA+="${RED}[!!!] FILELESS ${NC}"
            ES_AMENAZA=true
        fi

        local linea=$(printf "%-10s %-7s %-5s %-5s %-15s %-30s %b" "$user" "$pid" "$cpu" "$mem" "$stat" "${args:0:30}" "$ALERTA")

        if [ "$ES_AMENAZA" = true ]; then
            echo -e "$linea" >> "$tmp_amenazas"
        else
            echo -e "$linea" >> "$tmp_normales"
        fi
    done

	echo -e "--------------------------------------------------------------------------------"
	printf "%-10s %-7s %-5s %-5s %-15s %-30s %s" "USUARIO" "PID" "%CPU" "%MEM" "ESTADO" "COMANDO" "ALERTAS"
	echo -e "--------------------------------------------------------------------------------"

	if [ -s "$tmp_amenazas" ]; then
        	echo -e "${RED}>>> AMENAZAS DETECTADAS (Prioridad Alta) <<<${NC}"
        	cat "$tmp_amenazas"
        	echo -e "--------------------------------------------------------------------------------"
    	fi

   	 echo -e "${GREEN}>>> Procesos del Sistema (Top CPU) <<<${NC}"
   	 head -n 10 "$tmp_normales"

    	rm "$tmp_amenazas" "$tmp_normales"


    	echo -e "${YELLOW}[?] Ingrese PID para análisis profundo o 'n' para salir:${NC}"
    	read pid_gestion

    if [[ "$pid_gestion" =~ ^[0-9]+$ ]] && ps -p "$pid_gestion" > /dev/null; then
        echo -e "\n${GREEN}>>> ANÁLISIS DEL PID $pid_gestion <<<${NC}"
        
	
        local ppid=$(ps -p "$pid_gestion" -o ppid= | tr -d ' ') #clave el tr, si no recibe un string el ps -p
        echo -e "${YELLOW}Padre del proceso (PPID):${NC} $ppid ($(ps -p "$ppid" -o comm= 2>/dev/null || echo "Desconocido"))"
        
        echo -e "${YELLOW}Conexiones de red activas:${NC}"
        if command -v ss > /dev/null; then
            ss -antp | grep "pid=$pid_gestion," || echo "Sin conexiones activas."

        echo -e "\nAcciones de respuesta:"
        echo "1) SIGSTOP (Congelar para investigar)"
        echo "2) SIGTERM (Cierre ordenado)"
        echo "3) SIGKILL (Eliminación inmediata)"
        echo "4) Volver al monitor"
        read -p "Opción: " sig_opcion

        case $sig_opcion in
            1) kill -19 "$pid_gestion" && echo -e "${BLUE}Proceso suspendido.${NC}" ;;
            2) kill -15 "$pid_gestion" && echo -e "${YELLOW}Señal SIGTERM enviada.${NC}" ;;
            3) kill -9 "$pid_gestion" && echo -e "${RED}Proceso eliminado.${NC}" ;;
            *) echo "Regresando..." ;;
        esac
    fi
}


if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: Este script debe ejecutarse como root (sudo) para ver todos los procesos y conexiones.${NC}"
   exit 1
fi

while true; do
    clear
    echo -e "${YELLOW}=== SENTINEL: SECURITY AUDIT TOOL ===${NC}"
    generate_sys_id  
    
    echo -e "${NC}Seleccione una categoría de análisis:"
    echo "1) SCAN LOGS (Intruders Detection & RegEx)"
    echo "2) PERMISSION AUDIT (FHS & Privilege Escalation)"
    echo "3) MONITOR PROCESSES (Live Tracking & Signals)"
    echo "4) EXIT"
    
    read -p "Option [1-4]: " option

    case $option in
        1) 
            check_suspicius_logs 
            ;;
        2) 
            audit_permissions 
            ;;
        3) 
            monitor_processes 
            ;;
        4) 
            echo -e "${GREEN}[+] Sentinel shutting down. Stay safe, $USER.${NC}"
            exit 0 
            ;;
        *) 
            echo -e "${RED}[!] Invalid option. Try again.${NC}"
            sleep 1
            continue
            ;;
    esac

    
    echo -e "${YELLOW}--- Presione [ENTER] para volver al menú principal ---${NC}"
    read
done
