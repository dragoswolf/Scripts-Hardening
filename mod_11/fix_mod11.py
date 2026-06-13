#!/usr/bin/env python3
#=========================================================================================================
# fix_mod11.py - Script de fortificación para el módulo 11 - Detección de Intrusos de Host (AIDE)
#=========================================================================================================
# Este script implementa las siguientes medidas de seguridad:
#
#   Paso 1: Instalar AIDE
#   Paso 2: Inicializar la base de datos de AIDE
#   Paso 3: Programar verificación automática con cron
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo11_fix.log
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================

import os
import sys
import time

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

LOG_FILE="/var/log/hardening/modulo11_fix.log"

AIDE_CONF="/etc/aide/aide.conf"
AIDE_DB="/var/lib/aide/aide.db"
AIDE_DB_NEW="/var/lib/aide/aide.db.new"
CRON_AIDE="/etc/cron.daily/aide-check"

CRON_CONTENIDO="""
#!/bin/bash
#=========================================================================================================
# aide-check - Verificación diaria de integridad con AIDE
#=========================================================================================================
# Este script se ejecuta automáticamente a través de cron.daily. 
# Compara el estado actual del sistema con la base de datos de AIDE
# y registra los cambios detectados en /var/log/aide/aide-check.log
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================

LOG_DIR="/var/log/aide"
LOG_FILE="$LOG_DIR/aide-check.log"
FECHA=$(date '+%d-%m-%Y %H:%M:%S')

# Crear directorio de logs si no existe
mkdir -p "$LOG_DIR"

# Ejecutar verificación
echo "=========================================================================================================" >> "$LOG_FILE"
echo "Verificación AIDE: $FECHA" >> "$LOG_FILE"
echo "=========================================================================================================" >> "$LOG_FILE"

/usr/bin/aide --check >> "$LOG_FILE" 2>&1
RESULTADO=$?

if [ $RESULTADO -eq 0 ]; then
    echo "[CORRECTO]: Sin cambios detectados." >> "$LOG_FILE"
elif [ $RESULTADO -ge 1 ] && [ $RESULTADO -le 7 ]; then
    echo "[AVISO]: Se detectaron cambios en el sistema." >> "$LOG_FILE"
    # Registrar también en syslog para visibilidad.
    logger -t aide-check "AIDE detectó cambios en la integridad del sistema. Ver $LOG_FILE"
else
    echo "[ERROR]: Error al ejecutar AIDE (código: $RESULTADO)." >> "$LOG_FILE"
    logger -t aide-check "Error al ejecutar AIDE (código: $RESULTADO)"
fi

echo "" >> "$LOG_FILE"
"""
#=========================================================================================================


def paso1_instalar_aide():
    """
    Instala el paquete AIDE si no está presente.
    """
    print()
    print("="*100)
    print("[PASO 1]: Instalar AIDE.")
    print("="*100)
    print_info("Instala AIDE si no está presente.")
    print()

    paso="Paso 1"


    # 1a. Verificar/instalar AIDE
    rc,_,_=ejecutar_comando_check(["dpkg", "-s", "aide"])
    if rc!=0:
        print_info("Instalando AIDE...")
        print_info("Esta operación puede tardar unos minutos.")
        print()

        # Configurar la variable de entorno para saltarnos la instalación interactiva
        os.environ["DEBIAN_FRONTEND"]="noninteractive"

        if not ejecutar_comando(["apt", "install", "-y","aide","aide-common"], "instalarAIDE", paso, mostrarSalida=True):
            return
        else:
            print_correcto("AIDE instalado correctamente")

        print()

        # 1b. Verificar que el binario existe
        rc, salida, _= ejecutar_comando_check(["which", "aide"])
        if rc==0:
            print_correcto(f"Binario AIDE encontrado: {salida.strip()}")
        else:
            if os.path.isfile("/usr/bin/aide"):
                print_correcto("Binario AIDE encontrado en /usr/bin/aide")
            else:
                print_aviso("No se encontró el binario de AIDE.")
                registrar_errores(paso, "Binario AIDE no encontrado.")

        # 1c. Verificar configuración
        if os.path.isfile(AIDE_CONF):
            print_correcto(f"Fichero de configuración existe en {AIDE_CONF}.")
        else:
            print_info("El fichero de configuración se generará al inicializar la base de datos.")
    else:
        print_correcto("AIDE ya está instalado")


def paso2_inicializar_db():
    """
    Inicializa la base de datos de AIDE. Si ya existe una base de datos,
    pregunta al usuario si desea regenerarla.
    """
    print()
    print("="*100)
    print("[PASO 2]: Inicializar/regenerar Base de Datos.")
    print("="*100)
    print_info("Inicializa la base de datos de AIDE. Si ya existe una base de datos,\n" \
    "           pregunta al usuario si desea regenerarla.")
    print()

    paso="Paso 2"

    # 2a. Verificar que AIDE está instalado
    rc,_,_=ejecutar_comando_check(["dpkg", "-s", "aide"])
    if rc!=0:
        print_error("AIDE no está instalado. Ejecuta el paso 1 primero.")
        return
    
    # 2b. Verificar si ya existe una base de datos.
    if os.path.isfile(AIDE_DB):
        print_info("Ya existe una base de datos de AIDE:")
        try:
            mtime=os.path.getmtime(AIDE_DB)
            fecha=time.strftime("%d-%m-%Y %H:%M:%S", time.localtime(mtime))
            tamano=os.path.getsize(AIDE_DB)

            print(f"    Fecha:  {fecha}")
            print(f"    Tamaño: {tamano//1024} KB")
        except OSError:
            pass

        print()

        resp=input("¿Deseas regenerar la base de datos? (s/n): ").strip().lower()
        if resp!="s":
            print_info("Base de datos existente conservada.")
            return
    
    print()
    print_info("Inicializando la base de datos de AIDE...")
    print_info("Esta operación puede tardar varios minutos.")
    print()

    # 2c. Regenerar o inicializar la base de datos.
    # Usar aideinit que es el wrapper de ubuntu para aide --init
    if not ejecutar_comando(["aideinit"], "inicializar base de datos AIDE", paso, mostrarSalida=True):
        #puede que aideinit no exista, en ese caso, intentarlo con el comando base
        if not ejecutar_comando(["aide", "--init"], "inicializar base de datos AIDE", paso, mostrarSalida=True):
            return
        else:
            print_correcto("Base de datos de AIDE inicializada. Aplicando el resto de las configuraciones...")
        
        if os.path.isfile(AIDE_DB_NEW):
            if not ejecutar_comando(["cp", AIDE_DB_NEW, AIDE_DB], "copiar base de datos AIDE", paso):
                return
            else:
                print_correcto("Base de datos generada y activada")
        else:
            print_error("No se pudo generar la base de datos.")
            registrar_errores(paso, "aide --init no generó aide.db.new")
            return
    else:
        print_correcto("Base de datos de AIDE inicializada correctamente.")

    if os.path.isfile(AIDE_DB):
        try:
            tamano=os.path.getsize(AIDE_DB)
            print_info(f"Tamaño de la base de datos: {tamano//1024} KB.")
        except OSError:
            pass

    print()
    print_info( "Esta base de datos representa el estado 'limpio' del sistema." \
                " Es muy importante asegurarse de que el sistema no está comprometido" \
                " antes de considerar esta base de datos como referencia.")
    print()



def paso3_programar_cron():
    """
    Crea un script en cron.daily para ejecutar la verificación de AIDE automáticamente cada día.
    """
    print()
    print("="*100)
    print("[PASO 3]: Programar verificación automática con cron.")
    print("="*100)
    print_info("Crea un script en cron.daily para ejecutar la verificación de AIDE automáticamente\n" \
    "cada día.")
    print()

    paso="Paso 3"

    # 3a. Verificar que AIDE está instalado
    rc, _,_=ejecutar_comando_check(["dpkg", "-s", "aide"])

    if rc!=0:
        print_error("AIDE no está instalado. Ejecuta el paso 1 primero.")
        return
    
    # 3b. Verificar que existe una base de datos de AIDE
    if not os.path.isfile(AIDE_DB):
        print_aviso("No existe base de datos de AIDE. Ejecuta el paso 2 primero.")
        print()
    
    # 3c. Verificar si existe el script cron
    if os.path.isfile(CRON_AIDE):
        print_info(f"Ya existe un script cron para AIDE: {CRON_AIDE}")
        print()

        resp=input("¿Desea reemplazarlo con la configuración estándar? (s/n): ").strip().lower()
        if resp!="s":
            print_info("Script cron existente conservado.")
            return
        
    # 3d. Crear el script cron
    print_info("Creando script de verificación diaria...")
    if not escribir_fichero(CRON_AIDE, CRON_CONTENIDO, permisos=0o755, paso=paso):
        return
    else:
        print_correcto(f"Script cron creado: {CRON_AIDE}")

    # 3e. Crear directorio de logs de AIDE
    dirLogAide="/var/log/aide"
    if not os.path.isdir(dirLogAide):
        if not ejecutar_comando(["mkdir", "-p", dirLogAide], f"crear {dirLogAide}", paso):
            return
        else:
            print_correcto(f"Directorio de logs creado en {dirLogAide}.")
    
    # 3f. Verificar que cron está activo
    rc,_,_=ejecutar_comando_check(["systemctl", "is-active", "--quiet", "cron"])
    if rc==0:
        print_correcto("Servicio cron activo.")
    else:
        print_info("Activando servicio cron...")

        if not ejecutar_comando(["systemctl", "enable", "--now", "cron"], "activar cron", paso):
            return
        else:
            print_correcto("Servicio cron activado.")
    
    # 3f. Ejecutar primera verificación para generar registro inicial.
    print()
    print_info("Ejecutando primera verificación para generar registro inicial.")
    print_info("Esto puede tardar unos minutos...")
    print()
    if not ejecutar_comando(["bash", CRON_AIDE], "ejecutar verificación inicial de AIDE", paso, mostrarSalida=True):
        return
    else:
        print_correcto("Verificación inicial completada.")

    print()
    print_info("La verificación se ejecutará diariamente." \
    " Los resultados se guardarán en: /var/log/aide/aide_check.log")
    print()
    print_info("Si AIDE detecta cambios, enviará un aviso a syslog" \
    " (visible en /var/log/syslog).")
    print_info("Para leer el registro, simplemente usa 'cat /var/log/aide/aide-check.log'")
    print_info("Esto reportará los cambios realizados. Si los cambios que se ven son aquellos realizados" \
    " por el usuario, no hay problema, pero si detecta cambios realizados sin que haya sido el usuario," \
    " se recomienda una investigación.")


def mostrar_menu():
    print()
    print("="*100)
    print("MÓDULO 11: DETECCIÓN DE INTRUSOS DE HOST (AIDE).")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Instalar AIDE.")
    print("     2. Inicializar base de datos.")
    print("     3. Programar verificación automática (cron).")
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
                paso1_instalar_aide()
                volver_al_menu()
            case "2":
                paso2_inicializar_db()
                volver_al_menu()
            case "3":
                paso3_programar_cron()
                volver_al_menu()
            case "q":
                print("\n[INFO]: Saliendo del script.")
                sys.exit(0)
            case _:
                print_error("Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()
    
    

            