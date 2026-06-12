#!/usr/bin/env python3

#=========================================================================================================
# fix_mod11.py - Script de fortificación para el módulo 11 - Configuración y Supervisión de Logs
#=========================================================================================================

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging,
                   comprobar_root,
                   ejecutar_comando_check,
                   volver_al_menu,
                   resultado_fail,
                   resultado_ok,
                   resultado_warn,
                   registrar_errores,
                   contadores,
                   mostrar_resumen,
                   verificar_antiguedad)


#=========================================================================================================
# CONSTANTES
#=========================================================================================================

LOG_FILE="/var/log/hardening/modulo11_fix.log"

AIDE_CONF="/etc/aide/aide.conf"
AIDE_DB="/var/lib/aide/aide.db"
AIDE_DB_NEW="/var/lib/aide/aide.db.new"
CRON_AIDE="/etc/cron.daily/aide-check"

ALTERNATIVAS_CRON=[
    "/etc/cron.daily/aide",
    "/etc/cron.d/aide",
]


#=========================================================================================================


def verificar_paso1():
    """
    Verifica que AIDE está instalado y que el binario es accesible.
    """
    print()
    print("="*100)
    print("[PASO 1]: Verificar que AIDE está instalado.")
    print("="*100)
    print()

    paso="Paso 1"

    # 1a. Verificar que AIDE está instalado
    rc, _,_=ejecutar_comando_check(["dpkg", "-s", "aide"])
    if rc==0:
        resultado_ok("Paquete AIDE instalado.")
    else:
        resultado_fail("Paquete AIDE no está instalado.", paso)
        return
    
    # 1b. Verificar que el paquete aide-common está instalado
    rc, _,_=ejecutar_comando_check(["dpkg", "-s", "aide-common"])
    if rc==0:
        resultado_ok("Paquete aide-common instalado")
    else:
        resultado_warn("Paquete aide-common no instalado (puede faltar configuración por defecto).")
    
    # 1c. Verificar binario accesible.
    if os.path.isfile("/usr/bin/aide"):
        resultado_ok("Binario AIDE accesible (/usr/bin/aide).")
    else:
        rc, salida,_=ejecutar_comando_check(["which", "aide"])
        if rc==0:
            resultado_ok(f"Binario AIDE accesible ({salida.strip()})")
        else:
            resultado_fail("Binario AIDE no encontrado en el PATH", paso)
    
    # 1d. Verificar configuración existente
    if os.path.isfile("/etc/aide/aide.conf"):
        resultado_ok("Fichero de configuración existe (/etc/aide/aide.conf).")
    else:
        resultado_warn("Fichero /etc/aide/aide.conf no encontrado.")


def verificar_paso2():
    """
    Verifica que la base de datos existe y está activa.
    """
    print()
    print("="*100)
    print("[PASO 2]: Verificar base de datos de AIDE.")
    print("="*100)
    print()

    paso="Paso 2"

    # 2a. Verificar la existencia de la DB
    if os.path.isfile(AIDE_DB):
        resultado_ok(f"Base de datos existe ({AIDE_DB})")

        # 2b. Si existe la DB, verificar si todo está correcto
        dias = verificar_antiguedad(AIDE_DB, "Última actualización", mostrarTamano=True)
        if dias is not None and dias >30:
            resultado_warn(f"La base de datos tiene {int(dias)} dias de antiguedad. Actualizar con 'aide --update'")

    else:
        resultado_fail("Base de datos NO existe. Ejecuta el paso 2 del módulo 11 para inicializarla.", paso)



def verificar_paso3():
    """
    Verifica que existe un script cron para la verificación automática de AIDE y que cron está activo.
    """

    print()
    print("="*100)
    print("[PASO 3]: Verificar verificación automática mediante cron.")
    print("="*100)
    print()

    paso="Paso 3"

    # 3a. Verificar que el script existe
    if os.path.isfile(CRON_AIDE):
        resultado_ok(f"Script cron existe en {CRON_AIDE}.")

        # 3b. Verificar que es ejecutable
        if os.access(CRON_AIDE, os.X_OK):
            resultado_ok("Script cron tiene permisos de ejecución.")
        else:
            resultado_fail("Script cron no tiene permisos de ejecución", paso)
    else:
        #Buscar alternativas por que AIDE puede crear su propio cron
        encontrado=False
        for alt in ALTERNATIVAS_CRON:
            if os.path.isfile(alt):
                resultado_ok(f"Script cron alternativo encontrado ({alt}).")
                encontrado=True
                break

        if not encontrado:
            resultado_fail("No hay verificación automática programada. Ejecuta el paso 3 del módulo 11", paso)

    # 3c. Verificar servicio cron activo
    rc, _,_=ejecutar_comando_check(["systemctl", "is-active", "--quiet", "cron"])
    if rc==0:
        resultado_ok("Servicio cron activo")
    else:
        resultado_fail("Servicio cron no está activo", paso)

    # 3d. Verificar el directorio de logs de AIDE
    dirLogAide="/var/log/aide"
    if os.path.isdir(dirLogAide):
        resultado_ok(f"Directorio de logs AIDE existe ({dirLogAide}).")

        # 3e. Verificar si hay logs recientes
        logFile=os.path.join(dirLogAide, "aide-check.log")
        if os.path.isfile(logFile):
           
            dias = verificar_antiguedad(logFile, "Último log de verificación")
            if dias is not None and dias > 2:
                resultado_warn(f"El último log tiene {int(dias)} días. La verificación diaria podría no estar ejecutándose.")

        else:
            resultado_warn("No hay logs de verificación todavía. Se generará en la próxima ejecución de cron.")
    else:
        resultado_warn(f"{dirLogAide} no existe. Se creará con la primera verificación")


def main():
    """
    Ejecuta todas las verificaciones del módulo 11 y muestra el resumen final.
    """
    comprobar_root()
    configurar_logging(LOG_FILE)

    print()
    print("="*100)
    print("[AUDITORÍA MÓDULO 11]: DETECCIÓN DE INTRUSOS (AIDE)")
    print("="*100)
    print()

    print()
    print("     Comprobando configuraciones de los pasos 1 al 3...")
    print()

    verificar_paso1()
    verificar_paso2()
    verificar_paso3()


    mostrar_resumen("fix_mod11.py")

    if contadores["checksFail"]>0:
        sys.exit(1)
    else:
        sys.exit(0)

# =============================================================================
if __name__ == "__main__":
    main()



