#!/usr/bin/env python3

#=========================================================================================================
# check_mod12.py - Script de verificación para el módulo 12 - Antimalware
#=========================================================================================================

import os
import sys
import time


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging,
                comprobar_root,
                ejecutar_comando_check,
                resultado_fail,
                resultado_ok,
                resultado_warn,
                mostrar_resumen,
                contadores,
                leer_fichero               
                )

#=========================================================================================================
# CONSTANTES
#=========================================================================================================
LOG_FILE="/var/log/hardening/modulo12_check.log"

CRON_CLAMAV="/etc/cron.weekly/clamav-scan"
CRON_RKHUNTER="/etc/cron.weekly/rkhunter-scan"
#=========================================================================================================

def verificar_paso1():
    """
    Verifica que ClamAV está instalado, que freshclam está activoy que la base de datos de firmas existe
    """

    print()
    print("="*100)
    print("[PASO 1]: Verificar ClamAV y sus componentes.")
    print("="*100)
    print()

    paso="Paso 1"

    # 1a. Verificar paquetes instalados
    for paquete in ["clamav", "clamav-daemon"]:
        rc,_,_=ejecutar_comando_check(["dpkg", "-s", paquete])
        if rc==0:
            resultado_ok(f"Paquete {paquete} instalado.")
        else:
            resultado_fail(f"Paquete {paquete} no instalado.", paso)
        
    # 1b. Verificar que freshclam está activo
    rc,_,_=ejecutar_comando_check(["systemctl", "is-active", "--quiet", "clamav-freshclam"])

    if rc==0:
        resultado_ok("Servicio freshclam activo (actualización automática de firmas).")
    else:
        resultado_fail("Servicio freshclam no está activo.", paso)
    
    # 1c. Comprobar la existencia de la base de datos de firmas
    dbPaths=[
        "/var/lib/clamav/main.cvd",
        "/var/lib/clamav/main.cld",
    ]

    dbEncontrada=False
    for dbPath in dbPaths:
        if os.path.isfile(dbPath):
            dbEncontrada=True
            try:
                mtime=os.path.getmtime(dbPath)
                fecha=time.strftime("%d-%m-%Y %H:%M:%S", time.localtime(mtime))
                resultado_ok(f"Base de datos de firmas existe (actualizada: {fecha})")

                diasAntig=(time.time()-mtime)/86400
                if diasAntig>7:
                    resultado_warn(f"Base de datos tiene {int(diasAntig)} días (ejecutar 'freshclam' para actualizar)")
            except OSError:
                resultado_ok("Base de datos de firmas existe")
            break
    
    if not dbEncontrada:
        resultado_fail("Base de datos de firmas no encontrada (ejecutar freshclam)", paso)


def verificar_paso2():
    """
    Verifica que existe un script cron para escaneo automático con ClamAV
    """
    print()
    print("="*100)
    print("[PASO 2]: Verificar escaneo automático de ClamAV.")
    print("="*100)
    print()

    paso="Paso 2"

    # 2a. Script cron existe
    if os.path.isfile(CRON_CLAMAV):
        resultado_ok(f"Script cron existe ({CRON_CLAMAV})")

        if os.access(CRON_CLAMAV, os.X_OK):
            resultado_ok("Script cron tiene permisos de ejecución.")
        else:
            resultado_fail("Script cron no tiene permisos de ejecución.", paso)
    else:
        resultado_fail("No hay escaneo automático de ClamAV programado. Ejecuta el paso 2.", paso)
    

    # 2b. Verificar logs de escaneo
    logClamav="/var/log/clamav/clamav-scan.log"
    if os.path.isfile(logClamav):
        try:
            mtime=os.path.getmtime(logClamav)
            fecha=time.strftime("%d-%m-%Y %H:%M:%S", time.localtime(mtime))
            resultado_ok(f"Último escaneo registrado: {fecha}")

            diasAntig=(time.time()-mtime)/86400
            if diasAntig>8:
                resultado_warn(f"El último escaneo tiene {int(diasAntig)} días (el escaneo semanal podría no estar ejecutándose)")
        except OSError:
            pass
    else:
        resultado_warn("No hay logs de escaneo todavía, se generarán en la próxima ejecución.")



def verificar_paso3():
    """
    Verifica que RKHunter está instalado y que su base de datos de prpiedades existe.
    """
    print()
    print("="*100)
    print("[PASO 3]: Verificar que RKHunter está instalado y operativo.")
    print("="*100)
    print()

    paso="Paso 3"

    # 3a. Verificar que los paquetes están instalados
    rc,_,_=ejecutar_comando_check(["dpkg","-s","rkhunter"])
    if rc==0:
        resultado_ok("Paquete RKHunter y sus componentes instalados.")
    else:
        resultado_fail("Paquete RKHunter y sus componentes no están instalados.", paso)
        return
    
    # 3b. Verificar que el binario es accesible.
    rc,_,_=ejecutar_comando_check(["which", "rkhunter"])
    if rc==0:
        resultado_ok("Binario RKHunter disponible.")
    else:
        resultado_fail("Binario RKHunter no encontrado.", paso)

    # 3c. Verificar configuración de rkhunter.conf
    confRkhunter="/etc/rkhunter.conf"
    contenido=leer_fichero(confRkhunter)
    if contenido:
        lineas=contenido.splitlines()

        if any(l.strip().startswith("ALLOWDEVFILE=/dev/shm/pulse") for l in lineas):
            resultado_ok("ALLOWDEVFILE configurado /dev/shm.")
        else:
            resultado_warn("ALLOWDEVFILE no está configurado. Posibles falsos positivos")
    else:
        resultado_fail("No se pudo leer /etc/rkhunter.conf", paso)

    # 3d. Verificar que existe la base de datos de propiedades
    rkhunterDb="/var/lib/rkhunter/db/rkhunter.dat"
    if os.path.isfile(rkhunterDb):
        resultado_ok("Base de datos de propiedades existe.")
        try:
            mtime=os.path.getmtime(rkhunterDb)
            fecha=time.strftime("%d-%m-%Y %H:%M:%S", time.localtime(mtime))
            resultado_ok(f"Última actualización: {fecha}")

            diasAntig=(time.time()-mtime)/86400
            if diasAntig>30:
                resultado_warn(f"Base de datos tiene {int(diasAntig)} días. Considerar actualizar con 'rkhunter --propupd'.")
        except OSError:
            pass
    else:
        resultado_warn("Base de datos de propiedades no encontrada. Ejecutar 'rkhunter --propupd'.")


def verificar_paso4():
    """
    Verifica que existe un script cron para escaneo automático con RKHunter.
    """
    print()
    print("="*100)
    print("[PASO 4]: Verificar escaneo automático de RKHunter.")
    print("="*100)
    print()

    paso="Paso 4"

    # 4a. Script cron existe
    if os.path.isfile(CRON_RKHUNTER):
        resultado_ok(f"Script cron existe ({CRON_RKHUNTER}).")

        if os.access(CRON_RKHUNTER, os.X_OK):
            resultado_ok("Script cron tiene permisos de ejecución")
        else:
            resultado_fail("Script cron no tiene permisos de ejecución.", paso)
    else:
        if os.path.isfile("/etc/cron.daily/rkhunter") or os.path.isfile("/etc/cron.weekly/rkhunter"):
            resultado_ok("Script cron del paquete RKHunter encontrado.")
        else:
            resultado_fail("No hay escaneo automático de RKHunter programado. Ejecuta el paso 4.", paso)
    
    # 4b. Servicio cron activo
    rc, _,_=ejecutar_comando_check(["systemctl", "is-active", "--quiet", "cron"])
    if rc==0:
        resultado_ok("Servicio cron activo.")
    else:
        resultado_fail("Servicio cron no está activo.", paso)

    
    # 4c. Verificar logs de escaneo
    logRkhunter="/var/log/rkhunter/rkhunter-scan.log"
    if os.path.isfile(logRkhunter):
        resultado_ok("Logs de escaneo de RKHunter encontrados...")
        try:
            mtime=os.path.getmtime(logRkhunter)
            fecha=time.strftime("%d-%m-%Y %H:%M:%S", time.localtime(mtime))
            resultado_ok(f"Último escaneo registrado: {fecha}")

            diasAntig=(time.time()-mtime)/86400
            if diasAntig>8:
                resultado_warn(f"El último escaneo tiene {int(diasAntig)} días.")
        except OSError:
            pass
    else:
        resultado_warn("No hay logs de escaneo todavía.")


def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    print()
    print("="*100)
    print("[AUDITORÍA MÓDULO 12]: ANTIMALWARE")
    print("="*100)
    print()

    print()
    print("     Comprobando configuraciones de los pasos 1 al 4...")
    print()

    verificar_paso1()
    verificar_paso2()
    verificar_paso3()
    verificar_paso4()


    mostrar_resumen("fix_mod12.py")

    if contadores["checksFail"]>0:
        sys.exit(1)
    else:
        sys.exit(0)

# =============================================================================
if __name__ == "__main__":
    main()


