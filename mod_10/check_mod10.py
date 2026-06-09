#!/usr/bin/env python3

#=========================================================================================================
# check_mod10.py - Script de auditoría para el módulo 10 - Configuración y Supervisión de Logs
#=========================================================================================================


import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import(configurar_logging,
                  resultado_fail,
                  resultado_ok,
                  resultado_warn,
                  mostrar_resumen,
                  volver_al_menu,
                  ejecutar_comando_check,
                  leer_fichero,
                  contadores,
                  comprobar_root,
                  verificar_permisos)


LOG_FILE="/var/log/hardening/modulo10_check.log"

JOURNALD_CONF="/etc/systemd/journald.conf"
LOGROTATE_CONF="/etc/logrotate.d/rsyslog"

# Ficheros de log y sus permisos seguros (propietario:grupo modo)
FICHEROS_LOG={
    "/var/log/syslog": {"permisos":"640", "propietario":"syslog", "grupo":"adm"},
    "/var/log/auth.log":{"permisos":"640", "propietario":"syslog", "grupo":"adm"},
    "/var/log/kern.log":{"permisos":"640", "propietario":"syslog", "grupo":"adm"},
    "/var/log/mail.log":{"permisos":"640", "propietario":"syslog", "grupo":"adm"},
    "/var/log/dpkg.log":{"permisos":"640", "propietario":"root", "grupo":"adm"},
    "/var/log/ufw.log":{"permisos":"640", "propietario":"syslog", "grupo":"adm"},
}


def verificar_paso1():
    """
    Verifica que rsyslog está instalado, activo y habilitado en el arranque.
    """

    print()
    print("="*100)
    print("[PASO 1]: Verificar rsyslog instalado y activo.")
    print("="*100)
    print()

    paso="Paso 1"

    # 1a. Paquete instalado

    rc,_,_=ejecutar_comando_check(["dpkg", "-s", "rsyslog"])
    if rc==0:
        resultado_ok("Paquete 'rsyslog' instalado.")
    else:
        resultado_fail("Paquete 'rsyslog' NO instalado", paso)
        return
    
    # 1b. Servicio activo
    rc,_,_=ejecutar_comando_check(["systemctl", "is-active", "--quiet", "rsyslog"])
    if rc==0:
        resultado_ok("Servicio 'rsyslog' activo.")
    else:
        resultado_fail("Servicio 'rsyslog' NO está activo.", paso)

    
    # 1c. Habilitado en el arranque
    rc,_,_=ejecutar_comando_check(["systemctl", "is-enabled", "--quiet", "rsyslog"])

    if rc==0:
        resultado_ok("'rsyslog' habilitado en el arranque.")
    else:
        resultado_fail("'rsyslog' NO habilitado en el arranque.", paso)

    # 1d. Verificar existencia de ficheros log principales
    for fichero in ["/var/log/syslog", "/var/log/auth.log"]:
        nombre=os.path.basename(fichero)
        if os.path.isfile(fichero):
            resultado_ok(f"{nombre} existe")
        else:
            resultado_warn(f"{nombre} no existe ('rsyslog' puede no haber escrito aún).")


def verificar_paso2():
    """
    Verifica que 'journald' tiene Storage=persistent configurado y que el
    directorio /var/log/journal/ existe.
    """

    print()
    print("="*100)
    print("[PASO 2]: Verificar persistencia de journald.")
    print("="*100)
    print()

    paso="Paso 2"

    # 2a. Directorio de journal persistente
    dirJournal="/var/log/journal"
    if os.path.isdir(dirJournal):
        resultado_ok(f"{dirJournal} existe.")
    else:
        resultado_fail(f"{dirJournal} NO existe (los logs de journald se pierden tras reinicio)", paso)
    
    # 2b. Storage=persistent en journald.conf
    contenido=leer_fichero(JOURNALD_CONF)
    if contenido is None:
        resultado_fail(f"No se pudo leer {JOURNALD_CONF}", paso)
        return
    
    storagePersistent=False
    maxUseConfigurado=False

    for linea in contenido.splitlines():
        limpia=linea.strip()
        if limpia=="Storage-persistent":
            storagePersistent=True
        if limpia.startswith("SystemMaxUse=") and not limpia.startswith("#"):
            maxUseConfigurado=True

    if storagePersistent:
        resultado_ok("'journald' configurado con Storage=persistent.")
    else:
        resultado_fail("'journald' NO tiene Storage=persistent", paso)

    if maxUseConfigurado:
        resultado_ok("Tamaño máximo del journal configurado.")
    else:
        resultado_warn("SystemMaxUse no configurado en journald.conf (el journal podría crecer sin límite)")
    

    # 2c. Verificar que journald está activo
    rc,_,_=ejecutar_comando_check(["systemctl", "is-active", "--quiet", "systemd-journald"])
    if rc==0:
        resultado_ok("'systemd-journald' está activo.")
    else:
        resultado_fail("'systemd-journald' NO está activo", paso)


def verificar_paso3():
    """
    Verifica que los ficheros de log principales tienen permisos adecuados (no world-readable)
    """
    print()
    print("="*100)
    print("[PASO 3]: Verificar persistencia de journald.")
    print("="*100)
    print()

    paso="Paso 3"

    for fichero, config in FICHEROS_LOG.items():
        nombre=os.path.basename(fichero)

        if not os.path.isfile(fichero):
            continue

        verificar_permisos(fichero, permisosEsperados=config['permisos'], paso=paso)



def verificar_paso4():
    """
    Verifica que logrotate está instalado y configurado correctamente
    para los ficheros de log de rsyslog
    """
    print()
    print("="*100)
    print("[PASO 4]: Verificar configuración de logrotate.")
    print("="*100)
    print()

    paso="Paso 4"

    # 4a. Verificar instalación de logrotate
    rc, _,_=ejecutar_comando_check(["dpkg", "-s", "logrotate"])
    if rc==0:
        resultado_ok("'logrotate' instalado.")
    else:
        resultado_fail("'logrotate' NO instalado.", paso)
        return
    

    # 4b. COnfiguración de rsyslog en logrotate
    contenido=leer_fichero(LOGROTATE_CONF)
    if contenido is None:
        resultado_fail(f"{LOGROTATE_CONF} no existe o no pudo ser leído.", paso)
        return
    
    # Verificar parámetros
    if "weekly" in contenido:
        resultado_ok("Rotación semanal configurada.")
    elif "daily" in contenido:
        resultado_ok("Rotación diaria configurada.")
    else:
        resultado_warn("No se detecta frecuencia de rotación.")

    # Verificar retención
    retEncontrada=False
    for linea in contenido.splitlines():
        limpia=linea.strip()
        if limpia.startswith("rotate "):
            partes=limpia.split()
            if len(partes)>= 2 and partes[1].isdigit():
                semanas=int(partes[1])
                if semanas>= 8:
                    resultado_ok(f"Retención: {semanas} rotaciones.")
                else:
                    resultado_warn(f"Retención baja: {semanas} rotaciones (recomendado >= 8).")
                retEncontrada=True
                break

    if not retEncontrada:
        resultado_warn("No se encontró la directiva 'rotate' en configuración de 'rsyslog'.")

    
    # Verificar compresión
    if "compress" in contenido:
        resultado_ok("Compresión de logs activada")
    else:
        resultado_warn("Compresión de logs NO activada (los logs ocuparán más espacio).")

    
    # Verificar permisos de creación

    if "create 640" in contenido or "create 0640" in contenido:
        resultado_ok("Nuevos ficheros se crean con permisos 640")
    elif "create" in contenido:
        resultado_warn("Directiva 'create' existe pero no con permisos 640.")
    else:
        resultado_warn("No se encontró directiva 'create' para permisos de nuevos ficheros.")

    
    # 4c. Verificar sintaxis general
    rc,_, _=ejecutar_comando_check(["logrotate", "-d", "/etc/logrotate.conf"])

    if rc==0:
        resultado_ok("Sintaxis de 'logrotate' correcta.")
    else:
        resultado_warn("'logrotate' reportó advertencias al verificar la sintaxis.")


def main():
    """
    Ejecuta todas las verificaciones del módulo de logs y muestra el resumen final.
    """
    comprobar_root()
    configurar_logging(LOG_FILE)

    print()
    print("="*100)
    print("[AUDITORÍA MÓDULO 10]: CONFIGURACIÓN Y SUPERVISIÓN DE LOGS")
    print("="*100)
    print()

    print()
    print("     Comprobando configuraciones de los pasos 1 al 4...")
    print()

    verificar_paso1()
    verificar_paso2()
    verificar_paso3()
    verificar_paso4()


    mostrar_resumen("fix_mod10.py")

    if contadores["checksFail"]>0:
        sys.exit(1)
    else:
        sys.exit(0)

# =============================================================================
if __name__ == "__main__":
    main()