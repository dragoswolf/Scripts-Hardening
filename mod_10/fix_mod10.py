#!/usr/bin/env python3

#=========================================================================================================
# fix_mod10.py - Script de fortificación para el módulo 10 - Configuración y Supervisión de Logs
#=========================================================================================================


import os
import sys
import re
import pwd
import grp


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, 
                   registrar_errores, 
                   comprobar_root,
                   ejecutar_comando, 
                   ejecutar_comando_check, 
                   escribir_fichero,
                   leer_fichero,
                   cambiar_permisos, 
                   volver_al_menu,
                   print_aviso,
                   print_correcto,
                   print_error,
                   print_info)


LOG_FILE="/var/log/hardening/modulo10_fix.log"

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

LOGROTATE_CONTENIDO="""
/var/log/syslog
/var/log/mail.log
/var/log/kern.log
/var/log/auth.log
/var/log/mail.err
{
\tweekly
\trotate 12
\tcompress
\tdelaycompress
\tmissingok
\tnotifempty
\tcreate 640 syslog adm
\tsharedscripts
\tpostrotate
\t\t/usr/lib/rsyslog/rsyslog-rotate
\tendscript
}
"""

def paso1_rsylog():
    """
    Verifica que rsyslog está instalado y activo. Si no lo está, lo instala y lo habilita.
    """
    print()
    print("="*100)
    print("[PASO 1]: Verificar rsyslog instalado y activo.")
    print("="*100)
    print()

    paso="Paso 1"

    # 1a. Verificar instalación rsyslog
    rc, _, _ = ejecutar_comando_check(["dpkg", "-s", "rsyslog"])
    if rc!=0:
        print_info("Instalando rsyslog...")
        if not ejecutar_comando(["apt", "install", "-y", "rsyslog"], "instalar rsyslog", paso, mostrarSalida=True):
            return
        else:
            print_correcto("Rsyslog se ha instalado correctamente.")
        print()
    else:
        print_correcto("Rsyslog ya está instalado.")
    

    # 1b. Activiar y habilitar el servicio
    rc, salida, _= ejecutar_comando_check(["systemctl", "is-active", "--quiet", "rsyslog"])
    if rc!=0:
        print_info("Activando rsyslog...")
        if not ejecutar_comando(["systemctl", "start", "rsyslog"], "arrancar rsyslog", paso):
            return
        else:
            print_correcto("Rsyslog arrancado")
    else:
        print_correcto("Rsyslog ya está activo.")

    rc, _,_=ejecutar_comando_check(["systemctyl", "is-enabled", "--quiet", "rsyslog"])

    if rc!=0:
        if not ejecutar_comando(["systemctl", "enable", "rsyslog"], "habilitar rsyslog en el arranque", paso):
            return
        else:
            print_correcto("Rsyslog habilitado en el arranque.")
    else:
        print_correcto("Rsyslog ya está habilitado en el arranque")
    
    # 1c. Verificar que se están generando logs
    print()
    print_info("Verificando que los ficheros de log principales existen:")
    for fichero in ["/var/log/syslog", "/var/log/auth.log"]:
        if os.path.isfile(fichero):
            print_correcto(f"{fichero} existe.")
        else:
            print_aviso(f"{fichero} no existe aún, se creará con la primera escritura de rsyslog.")


def paso2_persistencia_journald():
    """
    Configura journald para almacenar los logs de forma persistente en /var/log/journal/
    """
    print()
    print("="*100)
    print("[PASO 2]: Configurar persistencia de journald.")
    print("="*100)
    print()

    paso="Paso 2"

    # 2a. Crear directorio de journal persistente
    dirJournal="/var/log/journal"
    if not os.path.isdir(dirJournal):
        print_info(f"Creando directorio {dirJournal}...")
        if not ejecutar_comando(["mkdir", "-p", dirJournal], f"crear {dirJournal}", paso):
            return
        else:
            print_correcto(f"Directorio {dirJournal} creado correctamente.")
        
        # Crear los permisos correctos para systemd-journal
        print_info("Configurando los permisos adecuados...")
        if not ejecutar_comando(["systemd-tmpfiles", "--create", "--prefix", "/var/log/journal"], "configurar permisos de journal", paso):
            return
        else:
            print_correcto(f"Permisos configurados correctamente para {dirJournal}.")
    else:
        print_correcto(f"El directorio {dirJournal} ya existe.")

    # 2b. Configurar Storage=persistent
    contenido=leer_fichero(JOURNALD_CONF)
    if contenido is None:
        registrar_errores(paso, f"No se pudo leer {JOURNALD_CONF}.")
        return
    
    # Buscar si ya existe Storage=persistent
    storageOk=False
    for linea in contenido.splitlines():
        limpia=linea.strip()
        if limpia=="Storage-persistent":
            storageOk=True
            break

    if storageOk:
        print_correcto("journald ya tiene almacenamiento persistente.")
    else:
        print_info(f"Configurando almacenamiento persistente en {JOURNALD_CONF}...")

        nuevasLineas=[]
        storageModificado=False

        for linea in contenido.splitlines():
            limpia=linea.strip()

            if limpia.startswith("#Storage=") or (limpia.startswith("Storage=") and limpia!="Storage-persistent"):
                nuevasLineas.append("Storage=persistent")
                storageModificado=True
            else:
                nuevasLineas.append(linea)

        
        # Si no habia storage, añadir debajo de [Journal]
        if not storageModificado:
            lineasFinal=[]
            for linea in nuevasLineas:
                lineasFinal.append(linea)
                if linea.strip()=="[Journal]":
                    lineasFinal.append("Storage=persistent")
            nuevasLineas=lineasFinal

        nuevoContenido="\n".join(nuevasLineas)
        if not nuevoContenido.endswith("\n"):
            nuevoContenido+="\n"

        escribir_fichero(JOURNALD_CONF, nuevoContenido, paso=paso)
        print_correcto("Storage=persistent configurado")

    # 2c. Configurar tamaño máximo del journal
    # Se limita a 500M
    maxUseOk=False
    for linea in contenido.splitlines():
        limpia=linea.strip()
        if limpia.startswith("SystemMaxUse=") and not limpia.startswith("#"):
            maxUseOk=True
            break

    if not maxUseOk:
        print_info("Configurando tamaño máximo del journal (500M)...")
        contenidoActual=leer_fichero(JOURNALD_CONF)

        if contenidoActual:
            nuevasLineas=[]
            maxUseAnadido=False

            for linea in contenidoActual.splitlines():
                limpia=linea.strip()
                if limpia.startswith("#SystemMaxUse="):
                    nuevasLineas.append("SystemMaxUse=500M")
                    maxUseAnadido=True
                else:
                    nuevasLineas.append(linea)

            if not maxUseAnadido:
                lineasFinal=[]
                for linea in nuevasLineas:
                    lineasFinal.append(linea)
                    if linea.strip()=="Storage=persistent":
                        lineasFinal.append("SystemMaxUse=500M")
                nuevasLineas=lineasFinal
            
            nuevoContenido="\n".join(nuevasLineas)
            if not nuevoContenido.endswith("\n"):
                nuevoContenido+="\n"

            escribir_fichero(JOURNALD_CONF, nuevoContenido, paso=paso)
            print_correcto("SystemMaxUse=500M configurado.")
    else:
        print_correcto("Tamaño máximo del journal ya configurado.")

    # 2d. Reiniciar journald
    print()
    print_info("Reiniciando systemd-journald...")
    if not ejecutar_comando(["systemctl", "restart", "systemd-journald"], "reiniciar journald", paso):
        return
    else:
        print_correcto("Journald reiniciado con persistencia activa.")



def paso3_permisos_logs():
    """
    Configura y corrige los permisos de los ficheros de log principales
    """
    print()
    print("="*100)
    print("[PASO 3]: Asegurar permisos de ficheros de log.")
    print("="*100)
    print()

    paso="Paso 3"

    for fichero, config in FICHEROS_LOG.items():
        nombre=os.path.basename(fichero)

        if not os.path.isfile(fichero):
            print_info(f"{nombre} no existe (se omite).")
            continue

        if cambiar_permisos(fichero, 
                         permisos=int(config["permisos"], 8),
                         propietario=pwd.getpwnam(config["propietario"]).pw_uid,
                         grupo=grp.getgrnam(config["grupo"]).gr_gid,
                         paso=paso):
            print_correcto(f"{nombre} asegurado ({config['permisos']} {config['propietario']}:{config['grupo']}).")
    


def paso4_logrotate():
    """
    Configura logrotate para los ficheros de log de rsyslog con rotación semanal,
    12 semanas de retención y compresión
    """
    print()
    print("="*100)
    print("[PASO 4]: Configurar logrotate.")
    print("="*100)
    print()

    paso="Paso 4"

    # 4a. Verificar que logrotate está instalado
    rc,_,_=ejecutar_comando_check(["dpkg", "-s", "logrotate"])
    if rc!=0:
        print_info("Instalando logrotate...")
        ejecutar_comando(["apt", "install", "-y", "logrotate"], "instalar logrotate", paso, mostrarSalida=True)
    else:
        print_correcto("'logrotate' ya está instalado.")

    # 4b. Verificar configuración global
    confGlobal=leer_fichero("/etc/logrotate.conf")
    if confGlobal:
        print()
        print_info("Configurando global actual (/etc/logrotate.conf):")
        for linea in confGlobal.splitlines():
            limpia=linea.strip()
            variablesConfGlobal=["weekly", "daily", "monthly", "rotate", "compress", "create"]
            if limpia and not limpia.startswith("#"):
                if any (k in limpia for k in variablesConfGlobal):
                    print(f"    {limpia}")
    
    # 4c. Configurar rotación de rsyslog
    print()
    print_info("Configurando rotación de logs de rsyslog...")

    confActual=leer_fichero(LOGROTATE_CONF)

    yaConfigurado=False
    if confActual:
        if ("rotate 12" in confActual and "weekly" in confActual and "compress" in confActual and "create 640" in confActual):
            yaConfigurado=True

    if yaConfigurado:
        print_correcto("'logrotate' ya está configurado correctamente.")
    else:
        if escribir_fichero(LOGROTATE_CONF, LOGROTATE_CONTENIDO, paso):
            print_correcto("Configuración de logrotate actualizada:")
            print(" - Rotación: semanal")
            print(" - Retención: 12 semanas")
            print(" - Compresión: activada")
            print(" - Permisos nuevos ficheros: 640 syslog:adm")

    
    # 4d. Verificar sintaxis de logrotate
    print()
    print_info("Verificando sintaxis de 'logrotate'...")
    rc, salida, stderr=ejecutar_comando_check(["logrotate", "-d", "/etc/logrotate.conf"])

    if rc==0:
        print_correcto("Sintaxis de 'logrotate' correcta.")
    else:
        errorMsg=stderr.strip() if stderr.strip() else salida.strip()
        print_aviso(f"'logrotate' reportó advertencias: {errorMsg[:200]}")
        registrar_errores(paso, f"Advertencias de logrotate: {errorMsg[:200]}")



def mostar_menu():
    print()
    print("="*100)
    print("HARDENING: CONFIGURACIÓN Y SUPERVISIÓN DE LOGS.")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Verificar rsyslog instalado y activado.")
    print("     2. Configurar persistencia de journald.")
    print("     3. Asegurar permisos de ficheros de log.")
    print("     4. Configurar logrotate (retención y compresión).")
    print()
    print("     q. Salir")
    print()
        

def main():
    configurar_logging(LOG_FILE)
    comprobar_root()

    while True:
        mostar_menu()
        opcion=input("Selecciona una opción: ").strip().lower()

        match opcion:
            case "1":
                paso1_rsylog()
                volver_al_menu()
            case "2":
                paso2_persistencia_journald()
                volver_al_menu()
            case "3":
                paso3_permisos_logs()
                volver_al_menu()
            case "4":
                paso4_logrotate()
                volver_al_menu()
            case "q":
                print("\n[INFO]: Saliendo del script.")
                sys.exit(0)
            case _:
                print("[ERROR]: Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()
    