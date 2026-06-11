#!/usr/bin/env python3


#=========================================================================================================
# fix_mod12.py - Script de fortificación para el módulo 12 - Antimalware
#=========================================================================================================



import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging,
                   registrar_errores,
                   comprobar_root,
                   ejecutar_comando,
                   ejecutar_comando_check,
                   escribir_fichero,
                   leer_fichero,
                   volver_al_menu,
                   print_aviso,
                   print_correcto,
                   print_error,
                   print_info)


#=========================================================================================================
# CONSTANTES
#=========================================================================================================

LOG_FILE="/var/log/hardening/modulo12_fix.log"

CRON_CLAMAV="/etc/cron.weekly/clamav-scan"
CRON_RKHUNTER="/etc/cron.weekly/rkhunter-scan"

CRON_CLAMAV_CONTENIDO="""
#!/bin/bash
#=========================================================================================================
# clamav-scan - Escaneo semanal de malware con ClamAV
#=========================================================================================================
# Escanea los directorios críticos del sistema y registra los resultados
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================

LOG_DIR="/var/log/clamav"
LOG_FILE="$LOG_DIR/clamav-scan.log"
FECHA=$(date '+%d-%m-%Y %H:%M:%S')

# Crear directorio de logs si no existe
mkdir -p "$LOG_DIR"

# Ejecutar verificación
echo "=========================================================================================================" >> "$LOG_FILE"
echo "Escaneo ClamAV: $FECHA" >> "$LOG_FILE"
echo "=========================================================================================================" >> "$LOG_FILE"

# Actualizar base de datos antes de escanear
freshclam --quiet 2>/dev/null

# Escanear directorios críticos
clamscan -r --quiet --infected \\
    --exclude-dir="^/proc" \\
    --exclude-dir="^/sys" \\
    --exclude-dir="^/dev" \\
    --exclude-dir="^/run" \\
    --exclude-dir="^/snap" \\
    / >> "$LOG_FILE" 2>&1

RESULTADO=$?


if [ $RESULTADO -eq 0 ]; then
    echo "[CORRECTO]: Sin malware detectado." >> "$LOG_FILE"
elif [ $RESULTADO -eq 1 ]; then
    echo "[AVISO]: Se detectó malware. Revisar el log." >> "$LOG_FILE"
    # Registrar también en syslog para visibilidad.
    logger -t clamav-scan "ClamAV detectó malware. Ver $LOG_FILE"
else
    echo "[ERROR]: Error durante el escaneo (código: $RESULTADO)." >> "$LOG_FILE"
    logger -t clamav-scan "Error durante el escaneo de ClamAV (código: $RESULTADO)"
fi

echo "" >> "$LOG_FILE"
"""

CRON_RKHUNTER_CONTENIDO="""
#!/bin/bash
#=========================================================================================================
# rkhunter-scan - Escaneo semanal de rootkits con RKHunter
#=========================================================================================================
# Ejecuta un escaneo completo de rootkits y registra los resultados
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================

LOG_DIR="/var/log/rkhunter"
LOG_FILE="$LOG_DIR/rkhunter-scan.log"
FECHA=$(date '+%d-%m-%Y %H:%M:%S')

# Crear directorio de logs si no existe
mkdir -p "$LOG_DIR"

# Ejecutar verificación
echo "=========================================================================================================" >> "$LOG_FILE"
echo "Escaneo RKHunter: $FECHA" >> "$LOG_FILE"
echo "=========================================================================================================" >> "$LOG_FILE"

# Actualizar base de datos antes de escanear
rkhunter --update --quiet 2>/dev/null

# Ejecutar escaneo (--skip-keypress evita pausas interactivas)
rkhunter --check --skip-keypress --quiet --report-warnings-only >> "$LOG_FILE" 2>&1

RESULTADO=$?


if [ $RESULTADO -eq 0 ]; then
    echo "[CORRECTO]: Sin rootkits detectados." >> "$LOG_FILE"
else
    echo "[AVISO]: RKHunter detectó posibles problemas. Revisar el log." >> "$LOG_FILE"
    # Registrar también en syslog para visibilidad.
    logger -t rkhunter-scan "RKHunter detectó posibles problemas. Ver $LOG_FILE"
fi

echo "" >> "$LOG_FILE"
"""
#=========================================================================================================


def paso1_instalar_clamav():
    """
    Instala ClamAV y el demonio de actualización de firmas.
    """
    print()
    print("="*100)
    print("[PASO 1]: Instalar ClamAV y sus componentes.")
    print("="*100)
    print()

    paso="Paso 1"

    # 1a. Verificar/instalar paquetes
    paquetes=["clamav", "clamav-daemon"]
    paquetesFaltantes=[]

    for paquete in paquetes:
        rc,_,_=ejecutar_comando_check(["dpkg", "-s", paquete])
        if rc!=0:
            paquetesFaltantes.append(paquete)

    if paquetesFaltantes:
        print_info(f"Instalando: {', '.join(paquetesFaltantes)}...")
        os.environ["DEBIAN_FRONTEND"]="noninteractive"
        if not ejecutar_comando(["apt", "install", "-y"] + paquetesFaltantes, "instalar ClamAV", paso, mostrarSalida=True):
            return
        else:
            print_correcto("ClamAV instalado correctamente")
            print()
    else:
        print_correcto("ClamAV ya está instalado.")


    # 1b. Verificar que freshclam está disponible
    rc,_,_=ejecutar_comando_check(["which", "freshclam"])
    if rc==0:
        print_correcto("Freshclam (actualizador de firmas) disponible.")
    else:
        print_aviso("Freshclam no encontrado en el PATH. La instalación ha podido tener problemas.")
    

    # 1c. Verificar que clamscan está disponible
    rc, _,_=ejecutar_comando_check(["which", "clamscan"])
    if rc==0:
        print_correcto("Clamscan (escáner) disponible")
    else:
        print_aviso("Clamscan no encontrado en el PATH. La instalación ha podido tener problemas.")


def paso2_configurar_clamav():
    """
    Actualiza la base datos de ClamAV y crea un script cron para escaneo semanal automático.
    """
    print()
    print("="*100)
    print("[PASO 2]: Actualizar ClamAV y programar escaneos periódicos.")
    print("="*100)
    print()

    paso="Paso 2"

    # 2a. Verificar que ClamAV está instalado
    rc,_,_=ejecutar_comando_check(["dpkg", "-s", "clamav"])
    if rc!=0:
        print_error("ClamAV no está instalado. Ejecuta el paso 1 primero.")
        return
    
    # 2b. Parar el servicio freshclam si está corriendo
    print_info("Parando el servicio freshclam...")
    rc,_,_=ejecutar_comando_check(["systemctl", "stop", "clamav-freshclam"])
    if rc==0:
        print_correcto("Servicio freshclam parado correctamente.")
    else:
        print_aviso("Servicio freshclam no pudo ser parado.")

    # 2c. Actualizar base de datos.
    print_info("Actualizando base de datos de firmas...")
    print_info("Esto puede tardar unos minutos.")
    print()

    if not ejecutar_comando(["freshclam"], "actualizar base de datos de firmas", paso, mostrarSalida=True):
        print_aviso("'freshclam' terminó con advertencias.")
    
    # 2d. Reiniciar servicio freshclam
    rc1,_,stderr=ejecutar_comando_check(["systemctl", "start", "clamav-freshclam"])
    if rc1==0:
        print_correcto("ClamAV freshclam reiniciado correctamente.")
    else:
        print_aviso(f"Han habido problemas al reiniciar freshclam: {stderr.strip()[:200]}")

    rc2,_,stderr=ejecutar_comando_check(["systemctl", "enable", "clamav-freshclam"])
    if rc2==0:
        print_correcto("ClamAV freshclam habilitado correctamente.")
    else:
        print_aviso(f"Han habido problemas al reiniciar freshclam: {stderr.strip()[:200]}")
    
    if rc1==0 and rc2==0:
        print_correcto("Servicio freshclam activo.")
    

    # 2e. Crear scrip cron semanal
    print()
    
    if os.path.isfile(CRON_CLAMAV):
        print_info(f"Ya existe un script cron: {CRON_CLAMAV}.")
        resp=input("    ¿Reemplazarlo? (s/n): ").strip().lower()
        if resp!="s":
            print_info("Script cron existente conservado.")
            return
        
    print_info("Creando escaneo semanal automático...")
    if not escribir_fichero(CRON_CLAMAV, CRON_CLAMAV_CONTENIDO, permisos=0o755, paso=paso):
        print_error("Hubo problemas a la hora de crear el cron semanal.")
    else:
        print_correcto(f"Script cron creado: {CRON_CLAMAV}.")

    # Crear directorio de logs
    dirLog="/var/log/clamav"
    if not os.path.isdir(dirLog):
        if not ejecutar_comando(["mkdir", "-p", dirLog], f"crear {dirLog}", paso):
            print_error("Error al crear el directorio de logs para ClamAV.")
        else:
            print_correcto("Directorio de logs para ClamAV creado correctamente.")


    print()
    print_info("ClamAV realizará un escaneo semanal automático.")
    print_info("Los resultados se guardarán en: /var/log/clamav/clamav-scan.log")


def paso3_instalar_rkhunter():
    """
    Instala RKhunter y actualiza su base de datos de propiedades
    """

    print()
    print("="*100)
    print("[PASO 3]: Instalar RKHunter y sus componentes.")
    print("="*100)
    print()

    paso="Paso 3"

    # 3a. Verificar/instalar RKhunter
    rc,_,_=ejecutar_comando_check(["dpkg", "-s", "rkhunter"])
    if rc!=0:
        print_info("Instalando RKHunter...")
        os.environ["DEBIAN_FRONTEND"]="noninteractive"
        if not ejecutar_comando(["apt", "install", "-y", "rkhunter"], "instalar RKHunter", paso, mostrarSalida=True):
            return
        else:
            print_correcto("RKHunter instalado correctamente.")
    else:
        print_correcto("RKHunter ya está instalado.")
    
    # 3b. Verificar binario
    rc,_,_=ejecutar_comando_check(["which", "rkhunter"])
    if rc==0:
        print_correcto("Binario rkhunter disponible.")
    else:
        print_aviso("Binario rkhunter no encontrado en el PATH.")

    # 3c. Actualizar base de datos de propiedades
    print()
    print_info("Generando base de datos de propiedades del sistema...")
    if not ejecutar_comando(["rkhunter", "--propupd"], "generar base de datos de propiedades", paso, mostrarSalida=True):
        print_aviso("Error al generar propiedades.")
    else:
        print_correcto("Base de datos de propiedades generada.")

    # 3d. Configurar para reducir falsos positivos
    confRkhunter="/etc/rkhunter.conf"
    contenido=leer_fichero(confRkhunter)
    if contenido:
        modificado=False
        nuevasLineas=[]

        webCmdAnadido=False

        for linea in contenido.splitlines():
            limpia=linea.strip()

            # Permitir scripts en /dev que Ubuntu usa legítimamente
            if limpia=="#ALLOWDEVFILE=/dev/shm/pulse-shm-*":
                nuevasLineas.append("ALLOWDEVFILE=/dev/shm/pulse-shm-*")
                modificado=True
            elif limpia=="UPDATE_MIRRORS=0":
                nuevasLineas.append("UPDATE_MIRRORS=1")
                modificado=True
            elif limpia=="MIRRORS_MODE=1":
                nuevasLineas.append("MIRRORS_MODE=0")
                modificado=True
            elif limpia=='WEB_CMD="/bin/false"':
                nuevasLineas.append('#WEB_CMD="/bin/false"')
                modificado=True
            elif limpia=='#WEB_CMD="/bin/false"' and not webCmdAnadido:
                nuevasLineas.append(linea)
                nuevasLineas.append('WEB_CMD="/usr/bin/wget"')
                webCmdAnadido=True
                modificado=True
            else:
                nuevasLineas.append(linea)

        if modificado:
            nuevoContenido ="\n".join(nuevasLineas)
            if not nuevoContenido.endswith("\n"):
                nuevoContenido+="\n"
            if not escribir_fichero(confRkhunter, nuevoContenido, paso=paso):
                print_error("Error al escribir la configuración de RKHunter.")
            else:
                print_correcto("Configuración de RKHunter ajustada.")
        else:
            print_correcto("Configuración de RKHunter correcta.")



def paso4_configurar_rkhunter():
    """
    Actualiza la base de datos de RKHunter y crea un script cron para el escaneo semanal automático.
    """

    print()
    print("="*100)
    print("[PASO 4]: Actualizar RKHunter y programar escaneo.")
    print("="*100)
    print()

    paso="Paso 4"

    # Verificar que RKHunter está instalado
    rc,_,_=ejecutar_comando_check(["dpkg", "-s", "rkhunter"])
    if rc!=0:
        print_error("RKHunter no está instalado. Ejecuta el paso 3.")
        return
    
    # 4a. Actualizar base de datos de firmas
    print_info("Actualizando base de datos de firmas de RKHunter...")
    if not ejecutar_comando(["rkhunter", "--update"], "actualizar base de datos de RKHunter", paso, mostrarSalida=True):
        print_aviso("RKHunter terminó con advertencias.")
    else:
        print_correcto("Base de datos actualizada.")

    # 4b. Crear script cron semanal
    print()
    if os.path.isfile(CRON_RKHUNTER):
        print_info(f"Ya existe un script cron: {CRON_RKHUNTER}")
        resp=input("¿Reemplazarlo? (s/n): ").strip().lower()
        if resp!="s":
            print_info("Script cron existente conservado.")
            return
        
    print_info("Creando escaneo semanal automático...")
    if not escribir_fichero(CRON_RKHUNTER,CRON_RKHUNTER_CONTENIDO, permisos=0o755, paso=paso):
        print_error("Error al crear el script cron de RKHunter.")
    else:
        print_correcto(f"Script cron creado: {CRON_RKHUNTER}")

    
    # Crear directorio de logs
    dirLog="/var/log/rkhunter"
    if not os.path.isdir(dirLog):
        if not ejecutar_comando(["mkdir", "-p", dirLog], f"crear {dirLog}", paso):
            print_error("Error al crear el directorio de logs de RKHunter.")
        else:
            print_correcto("Directorio de logs de RKHunter creado correctamente.")
    
    # Verificar que cron está activo
    rc,_,_=ejecutar_comando_check(["systemctl", "is-active", "--quiet", "cron"])
    if rc==0:
        print_correcto("Servicio cron activo.")
    else:
        if not ejecutar_comando(["systemctl", "enable", "--now", "cron"], "activar cron", paso):
            print_error("Error al activar cron.")
        else:
            print_correcto("Servicio cron activado.")

    print()
    print_info("RKHunter realizará un escaneo semanal automático.")
    print_info("Los resultados se guardarán en: /var/log/rkhunter/rkhunter-scan.log")

def mostrar_menu():
    print()
    print("="*100)
    print("MÓDULO 12: ANTIMALWARE.")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Instalar ClamAV.")
    print("     2. Configurar ClamAV.")
    print("     3. Instalar RKHunter.")
    print("     4. Configurar RKHunter.")
    print()
    print("     q. Salir")
    print()
        

def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    while True:
        mostrar_menu()
        opcion=input("Selecciona una opción: ").strip().lower()

        match opcion:
            case "1":
                paso1_instalar_clamav()
                volver_al_menu()
            case "2":
                paso2_configurar_clamav()
                volver_al_menu()
            case "3":
                paso3_instalar_rkhunter()
                volver_al_menu()
            case "4":
                paso4_configurar_rkhunter()
                volver_al_menu()
            case "q":
                print()
                print_info("Saliendo del script...")
                sys.exit(0)
            case _:
                print_error("Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()



