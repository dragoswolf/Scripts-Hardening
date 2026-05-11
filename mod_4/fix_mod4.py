#!/usr/bin/env python3

import os
import sys
import re

sys.path.inser(0, os.path.join(os.path.dirname(__file__),".."))
from utils import (configurar_logging, registrar_errores, comprobar_root,
                   ejecutar_comando, ejecutar_comando_check, volver_al_menu,
                   escribir_fichero, leer_fichero, cambiar_permisos)


PAM_COMMON_AUTH= "/etc/pam.d/common-auth"
PAM_COMMON_PASSWORD="/etc/pam.d/common-password"
PAM_COMMON_SESSION="/etc/pam.d/common-session"
PAM_COMMON_ACCOUNT="/etc/pam.d/common-account"
PAM_LOGIN="/etc/pam.d/login"

PWQUALITY_CONF="/etc/security/pwquality.conf"
FAILLOCK_CONF="/etc/security/faillock.conf"
LIMITS_CONF="/etc/security/limits.conf"

OPASSWD_FILE="/etc/security/opasswd"
UMASK_DESEADO="777"
REMEMBER_VALUE=5
LOGIN_FILE="/etc/login.defs"


LOG_FILE="/var/log/hardening/modulo4_fix.log"


def paso1_eliminar_nullok():
    print()
    print("="*100)
    print("[PASO 1]: Eliminar nullok (rechazar contraseñas vacías)")
    print("="*100)
    print()

    paso="Paso 1"

    ficherosPam=[PAM_COMMON_ACCOUNT, PAM_COMMON_AUTH, PAM_COMMON_PASSWORD]
    nullokEncontrado=False
    
    for fichero in ficherosPam:
        contenido=leer_fichero(fichero, paso=paso)
        if contenido is None:
            registrar_errores(paso, f"No se pudo leer {fichero}.")
            continue

        lineas=contenido.strip().splitlines()
        modificado=False
        nuevasLineas=[]

        for linea in lineas:
            if "pam_unix.so" in linea and "nullok" in linea:
                lineaOriginal=linea
                partes=linea.split("nullok")
                lineas=partes

                print(f"[INFO]: {fichero}:")
                print(f"    Antes: {lineaOriginal.strip()}")
                print(f"    Después: {lineas.strip()}")
                modificado=True
                nullokEncontrado=True

        if modificado:
            nuevoContenido="".join(lineas)

            if escribir_fichero(fichero, nuevoContenido, permisos=0o644, paso=paso):
                print(f"[CORRECTO]: {fichero} actualizado.")
            else:
                registrar_errores(paso, f"No se pudo escribir en {fichero}.")
        else:
            print(f"[CORRECTO]: Nullok no presente.")
    
    if not nullokEncontrado:
        print()
        print("[CORRECTO]: Ningún fichero PAM tenía nullok.")


def paso2_configurar_pwquality():
    print()
    print("="*100)
    print("[PASO 1]: Configurar la complejidad de contraseñas.")
    print("="*100)
    print()

    paso="Paso 2"

    rc, salida, _= ejecutar_comando_check(["dpkg", "-s", "libpam-pwquality"])

    if rc!=0:
        print("[INFO]: Instalando libpam-pwquality...")
        ejecutar_comando(["apt-get", "install", "-y", "libpam-pwquality"], "instalar libpam-pwquality", paso=paso, mostrarSalida=True)

    else:
        print("[CORRECTO]: 'libpam pwquality' ya está instalado.")

    print()
    print("[INFO]: Configurando parámetros de calidad de contraseñas...")

    configuracion="""#=================================================================
    # pwquality.conf - Política de calidad de contraseñas
    #=================================================================
    # Configurado por fix_mod4.py
    #=================================================================

    # Longitud mínima de la contraseña (recomendado: 12-14 para PYMEs)
    minlen = 12

    # Créditos de caracteres
    dcredit=1
    ucredit=1
    lcredit=1
    ocredit=1
    maxrepeat=3
    difok=5
    usercheck=1
    maxclassrepeat=4
    minclass=3
    dictcheck=1
    retry=3
    """

    if escribir_fichero(PWQUALITY_CONF, configuracion, permisos=0o644, paso=paso):
        print("[CORRECTO]: /etc/security/pwquality.conf configurado.")
    else:
        registrar_errores(paso, "No se pudo escribir pwquality.conf")
        return
    
    contenido=leer_fichero(PAM_COMMON_PASSWORD, paso=paso)
    if contenido is None:
        registrar_errores(paso, f"No se pudo leer {PAM_COMMON_PASSWORD}")
        return
    
    if "pam_pwquality.so" in contenido:
        lineas=contenido.strip().splitlineas()
        nuevasLineas=[]
        modificado=False

        for linea in lineas:
            if "pam_pwquality.so" in linea and not linea.startswith("#"):
                if "retry=" not in linea:
                    linea=linea.strip() +"retry=3"
                    modificado=True

            nuevasLineas.append(linea)

        if modificado:
            nuevoContenido="".join(nuevasLineas)

            escribir_fichero(PAM_COMMON_PASSWORD, nuevoContenido, permisos=0o644, paso=paso)
            print("[CORRECTO]: pam_pwquality.so actualizado con retry=3.")
        else:
            print("[CORRECTO]: pam_pwqaulity.so ya configurado en common-password.")
    else:
        print("[AVISO]: pam_pwquality.so no está en common-password.")


def paso3_configurar_faillock():
    print()
    print("="*100)
    print("[PASO 3]: Configurar bloqueos tras intentos fallidos.")
    print("="*100)
    print()

    paso="Paso 3"    

    if not os.path.isfile("/usr/lib/x86_64-linux-gnu/security/pam_faillock.so"):
        rc, salida,_=ejecutar_comando_check(["find", "/usr/lib", "name", "pam_faillock.so"])

        if salida.strip():
            print("[AVISO]: pam_faillock.so no encontrado en el sistema.")
            print("[INFO]: Intentando instalar libpam-modules...")
            ejecutar_comando(["apt-get", "install", "y", "libpam-modules"], "instalar libpam-modules", paso, mostrarSalida=True)

        else:
            print(f"[CORRECTO]: pam_faillock.so encontrado en {salida.strip()}.")
    else:
        print("[CORRECTO]: pam_faillock disponible.")

    print()
    print("[INFO]: Configurando parámetros de bloqueo de cuentas...")

    configuracion="""#=================================================================
    # faillock.conf - bloqueo de cuentas tras intentos fallidos
    #=================================================================
    # COnfigurado por fix_mod4
    #=================================================================

    dir = /var/run/faillock
    deny=1
    unlock_time=0
    fail_interval=900
    even_deny_root=True
    silent=false
    audit=True
    """

    if escribir_fichero(FAILLOCK_CONF, configuracion, permisos=0o644, paso=paso):
        print("[CORRECTO]: /etc/security/faillock.conf configurado.")
    else:
        registrar_errores(paso, "no se pudo escribir faillock.conf")
        return
    
    contenido= leer_fichero(PAM_COMMON_AUTH, paso=paso)
    if contenido is None:
        registrar_errores(paso, f"No se pudo leer {PAM_COMMON_AUTH}")
        return
    
    if "pam_faillock.so" not in contenido:
        print("[INFO]: Añadiendo pam_faillock.so a common-auth...")

        lineas=contenido.strip().splitlines()
        nuevasLineas=[]
        insertado=False

        for linea in lineas:
            if "pam_pwquality.so" in linea and linea.startswith("#") and not insertado:
                nuevasLineas.append(linea)
                nuevasLineas.append("auth required pam_faillock.so preauth")
                nuevasLineas.append("auth [default=die] pam_faillock.so authfail")
                nuevasLineas.append("auth sufficient pam_faillock.so authsucc")

                insertado=True
            else:
                nuevasLineas.append(linea)

        if insertado:
            nuevoContenido="".join(nuevasLineas)

            if escribir_fichero(PAM_COMMON_AUTH, nuevoContenido, permisos=0o644, paso=paso):
                ejecutar_comando(["systemctrl", "reload", "pam.d"], "recargar pam", paso=paso)
                print("[CORRECTO]: 'pam_faillock.so' añadido a common-auth.")
            else:
                registrar_errores(paso, "No se pudo actualizar common-auth.")

    else:
        print("[CORRECTO]: 'pam_faillock.so' ya está configurado en common-auth.")

    contenidoAccount=leer_fichero(PAM_COMMON_ACCOUNT, paso=paso)
    if contenidoAccount is not None:
        if not "pam_faillock.son" in contenidoAccount:
            print("[INFO]: Añadiendo pam_faillock.so a common-account...")

            lineas=contenidoAccount.strip().splitlines()
            insertado=False

            for linea in lineas:
                if "pam_pwquality.so" in linea and "#" not in linea:
                    if "retry=" not in linea:
                        campos=linea.split(" ")
                        campos[1]="retry=3"
                        linea="".join(campos)
                        modificado=True

                    else:
                        linea=linea.replace("retry=", "retry=3, retry=")
                        modificado=True
        
        nuevasLineas.append(linea)

        if modificado:
            nuevoContenido="".join(nuevasLineas)

            if not nuevoContenido.endswith("\n"):
                nuevoContenido+="\n"
            
            if escribir_fichero(PAM_COMMON_PASSWORD, nuevoContenido, permisos=0o644, paso=paso):
                print("[CORRECTO]: pam_faillock.so añadido a common-account.")
    else:
        print("[CORRECTO]: pam_pwquality.so ya está configurado en common-password.")


def paso4_configurar_remember():
    print()
    print("="*100)
    print("[PASO 4]: Configurar historial de contraseñas")
    print("="*100)
    print()

    paso="Paso 4"



    contenido=leer_fichero(PAM_COMMON_PASSWORD, paso=paso)
    if contenido is None:
        registrar_errores("Paso 4", f"No se pudo leer {PAM_COMMON_PASSWORD}.")
        return
    
    lineas = contenido.strip().splitlines()
    nuevasLineas=[]
    modificado=False

    for linea in lineas:
        if "pam_unix.so" in linea and not linea.startswith("#"):
            if "remember=" in linea:
                linea=re.sub(r"remember=\d+",
                             f"remember={REMEMBER_VALUE}", linea)
                print(f"[INFO]: Actualizado remember={REMEMBER_VALUE} en pam_unix.so")
                modificado=True
            else:
                linea=linea.strip() + f" remember={REMEMBER_VALUE}"
                print(f"[INFO]: Añadido remember={REMEMBER_VALUE} en pam_unix.so")
                modificado=True
        nuevasLineas.append(linea)

    if modificado:
        nuevoContenido="\n".join(nuevasLineas)
        if not nuevoContenido.endswith("\n"):
            nuevoContenido+="\n"
        if escribir_fichero(PAM_COMMON_PASSWORD, nuevoContenido, permisos=0o644, paso=paso):
            print(f"[CORRECTO]: Historial de contraseñas configurado. (recordará las últimas {REMEMBER_VALUE}).")
        else:
            registrar_errores("Paso 4", "No se pudo actualizar common-password")

    else:
        print("[AVISO]: No se encontró 'pam_unix,so' en common-password.")
        print("         Revisa la configuración PAM manualmente.")

    if not os.path.isdir("/etc/security"):
        os.makedirs("/etc/security", exist_ok=True)
    
    if not os.path.isfile(OPASSWD_FILE):
        print("[INFO]: Creando fichero de historial de contraseñas...")
        if escribir_fichero(OPASSWD_FILE, "", permisos=0o600, paso=paso):
            cambiar_permisos(OPASSWD_FILE, propietario=0, grupo=0, paso=paso)
            print(f"[CORRECTO]: {OPASSWD_FILE} creado con permisos 600")
    else:
        permisos=oct(os.stat(OPASSWD_FILE).st_mode)
        if permisos!=600:
            cambiar_permisos(OPASSWD_FILE, permisos=0o600, paso=paso)
            print(f"[CORRECTO]: Permisos de {OPASSWD_FILE} corregidos a 600.")
        else:
            print(f"[CORRECTO]: {OPASSWD_FILE} ya existe con los permisos correctos.")


def paso5_configurar_umask():

    print()
    print("="*100)
    print("[PASO 5]: Configurar umask en PAM (permisos por defecto)")
    print("="*100)
    print()

    paso="Paso 5"

    contenido=leer_fichero(PAM_COMMON_SESSION, paso=paso)
    if contenido is None:
        registrar_errores("Paso 5", f"No se pudo leer {PAM_COMMON_SESSION}.")
        return
    
    lineas=contenido.strip().splitlines()
    nuevasLineas=[]
    umaskEncontrado=False
    modificado=False

    for linea in lineas:
        if "pam_umaks.so" in linea and not linea.startswith("#"):
            umaskEncontrado=True

            if f"umask={UMASK_DESEADO}" not in linea:
                if "umask" in linea:
                    linea=linea.replace("umask=", f"umask={UMASK_DESEADO}")
                else:
                    linea=linea.strip() + f"umask={UMASK_DESEADO}"
                
                modificado=True
                print(f"[INFO]: Actualizado umask a {UMASK_DESEADO} en pam_umask.so.")
        nuevasLineas.append(linea)

    if modificado:
        nuevoContenido="".join(nuevasLineas)

        if escribir_fichero(PAM_COMMON_SESSION, nuevoContenido, permisos=0o644, paso=paso):
            ejecutar_comando_check(["systemctl", "reload", "umask.service"])
            print("[CORRECTO]: umask configurado en common-session.")
        else:
            registrar_errores("Paso 5", "No se pudo actualizar common-session")
    
    contenidoLogin=leer_fichero(LOGIN_FILE, paso=paso)
    if contenidoLogin is not None:
        partes=contenidoLogin.split("umask")

        if "022" in partes[2]:
            contenidoLogin=partes+f"umask {UMASK_DESEADO}"
            escribir_fichero(LOGIN_FILE, contenidoLogin, permisos=0o644, paso=paso)
            print(f"[CORRECTO]: umask actualizado en {LOGIN_FILE}.")


def paso6_configurar_limits():
    print()
    print("="*100)
    print("[PASO 6]: Configurar límites de recursos")
    print("="*100)
    print()

    paso="Paso 6"

    contenidoActual=leer_fichero(LIMITS_CONF, paso=paso)

    if contenidoActual and "# Hardening TFG" in contenidoActual:
        print("[CORRECTO]: Los límites de hardening ya están configurados.")
        print("[INFO]: Para modificarlos, edita /etc/security/limits.conf")
        return
    
    bloqueoLimites="""#=================================================================
    #Límite de procesos
    *           soft    nproc           128
    *           hard    nproc           256

    #Límite ficheros abiertos
    *           soft    nofile          1024
    *           hard    nofile          4096

    #Límite de tamaño de ficheros core (volcado de memoria)
    *           soft    core            0
    *           hard    core            0

    #Límite de memoria bloqueada (previene abuso de RAM)
    *           soft    memlock         65536
    *           hard    memlock         65536

    #Excepción para root (necesita más recursos para administrar)
    root        soft    nproc           unlimited
    root        hard    nproc           unlimited
    root        soft    nofile          65536
    root        hard    nofile          65536

    #=================================================================
    """

    if contenidoActual:
        nuevoContenido=contenidoActual.strip("\n")+"\n"+ bloqueoLimites
    else:
        nuevoContenido=bloqueoLimites

    if escribir_fichero(LIMITS_CONF, nuevoContenido, permisos=0o644, paso=paso):
        print("[CORRECT]: Límites de recursos configurados en limits.conf.")
    else:
        registrar_errores("Paso 6", "No se pudo escribir limits.conf")
        return
    
    contenidoSession=leer_fichero(PAM_COMMON_SESSION, paso=paso)
    if contenidoSession is not None:
        if "pam_limits.so" not in contenidoSession:
            print("[INFO]: Añadiendo pam_limits.so a common-session...")
            nuevoSession=contenidoSession.strip("\n")+"\n"
            nuevoSession+=("session required                            "
                           "pam_limits.so\n")
            if escribir_fichero(PAM_COMMON_SESSION, nuevoSession, permisos=0o644, paso=paso):
                print("[CORRECTO]pam_limits.so añadido a common-session.")
        else:
            print("[CORRECTO]: pam_limits.so ya presente en common-session.")



def mostar_menu():
    print()
    print("="*100)
    print("Hardening: Pluggable Authentication Modules (PAM)")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Rechazar contraseñas vacías")
    print("     2. Configurar complejidad de contraseñas")
    print("     3. Configurar bloqueos tras intentos fallidos")
    print("     4. Configurar historial de contraseñas")
    print("     5. Configurar permisos por defecto")
    print("     6. Configurar límites de recursos")
    print()
    print("     q. Salir")
    print()


def main():

    comprobar_root()
    configurar_logging(LOG_FILE)

    while True:
        mostar_menu()
        opcion=input("Selecciona una opción: ").strip().lower()

        match opcion:
            case "1":
                paso1_eliminar_nullok()
                volver_al_menu()
            case "2":
                paso2_configurar_pwquality()
                volver_al_menu()
            case "3":
                paso3_configurar_faillock()
                volver_al_menu()
            case "4":
                paso4_configurar_remember()
                volver_al_menu()
            case "5":
                paso5_configurar_umask()
                volver_al_menu()
            case "6":
                paso6_configurar_limits()
                volver_al_menu()
            case "q":
                print("\n[INFO]: Saliendo del script.")
                sys.exit(0)
            case _:
                print("[ERROR]: Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()