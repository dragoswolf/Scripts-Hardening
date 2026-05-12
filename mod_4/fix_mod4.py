#!/usr/bin/env python3

import os
import sys
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__),".."))
from utils import (configurar_logging, registrar_errores, comprobar_root,
                   ejecutar_comando, ejecutar_comando_check, volver_al_menu,
                   escribir_fichero, leer_fichero, cambiar_permisos)


PAM_COMMON_AUTH= "/etc/pam.d/common-auth"
PAM_COMMON_PASSWORD="/etc/pam.d/common-password"
PAM_COMMON_SESSION="/etc/pam.d/common-session"
PAM_COMMON_ACCOUNT="/etc/pam.d/common-account"
PAM_LOGIN="/etc/pam.d/login"
PAM_FAILLOCK="/usr/lib/x86_64-linux-gnu/security/pam_faillock.so"

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

        lineas=contenido.splitlines()
        modificado=False
        nuevasLineas=[]

        for linea in lineas:
            if "pam_unix.so" in linea and "nullok" in linea:
                lineaOriginal=linea
                linea=linea.replace(" nullok", "")
                linea=linea.replace("nullok ", "")
                linea=linea.replace("nullok", "")

                print(f"[INFO]: {fichero}:")
                print(f"    Antes: {lineaOriginal.strip()}")
                print(f"    Después: {linea.strip()}")

                modificado=True
                nullokEncontrado=True
            nuevasLineas.append(linea)

        if modificado:
            nuevoContenido="\n".join(nuevasLineas)

            if not nuevoContenido.endswith("\n"):
                nuevoContenido+="\n"

            if escribir_fichero(fichero, nuevoContenido, permisos=0o644, paso=paso):
                print(f"[CORRECTO]: {fichero} actualizado.")
            else:
                registrar_errores(paso, f"No se pudo escribir en {fichero}.")
        else:
            print(f"[CORRECTO]: {fichero}: Nullok no presente.")
    
    if not nullokEncontrado:
        print()
        print("[CORRECTO]: Ningún fichero PAM tenía nullok.")


def paso2_configurar_pwquality():
    print()
    print("="*100)
    print("[PASO 2]: Configurar la complejidad de contraseñas.")
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

# Créditos de caracteres (valores negativos = mínimo obligatorio)
# -1 significa "al menos 1 carácter de este tipo"
dcredit = -1    # Mínimo 1 dígito (0-9)
ucredit = -1    # Mínimo 1 mayúscula (A-Z)
lcredit = -1    # Mínimo 1 minúscula (a-z)
ocredit = -1    # Mínimo 1 carácter especial (!@#$...)

# Máximo de caracteres consecutivos repetidos permitidos
maxrepeat=3

# Mínimo de caracteres diferentes respecto a la anterior contraseña
difok=5

# No permitir que la contraseña contenga el nombre de usuario
usercheck=1

# Máximo de caracteres consecutivos de la misma clase
maxclassrepeat=4

# Complejidad: rechazar contraseñas que no tengan al menos 3 clases
# de caracteres diferentes (mayúsculas, minúsculas, dígitos, especiales)
minclass=3

# Rechazar contraseñas de diccionarios (cracklib)
dictcheck=1

# Número de reintentos antes de devolver error
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
        lineas=contenido.splitlines()
        nuevasLineas=[]
        modificado=False

        for linea in lineas:
            if "pam_pwquality.so" in linea and not linea.strip().startswith("#"):
                if "retry=" not in linea:
                    linea=linea.rstrip() +" retry=3"
                    modificado=True

            nuevasLineas.append(linea)

        if modificado:
            nuevoContenido="\n".join(nuevasLineas)
            if not nuevoContenido.endswith("\n"):
                nuevoContenido+="\n"

            escribir_fichero(PAM_COMMON_PASSWORD, nuevoContenido, permisos=0o644, paso=paso)
            print("[CORRECTO]: pam_pwquality.so actualizado con retry=3.")
        else:
            print("[CORRECTO]: pam_pwquality.so ya configurado en common-password.")
    else:
        print("[AVISO]: pam_pwquality.so no está en common-password.")
        print("         Esto se configura automáticamente al instalar")
        print("         libpam-pwquality. Verifica la instalación.")
    

    print()
    print("[INFO]: Resumen de la política de contraseñas:")
    print("         - Longitud mínima: 12 caracteres")
    print("         - Al menos 1 dígito, 1 mayúscula, 1 minúscula, 1 especial")
    print("         - Máximo 3 caracteres consecutivos repetidos")
    print("         - Mínimo 5 caracteres diferentes respecto a la anterior")
    print("         - Verificación contra diccionario activada")


def paso3_configurar_faillock():
    print()
    print("="*100)
    print("[PASO 3]: Configurar bloqueos tras intentos fallidos.")
    print("="*100)
    print()

    paso="Paso 3"    

    if not os.path.isfile(PAM_FAILLOCK):
        rc, salida,_=ejecutar_comando_check(["find", "/usr/lib", "-name", "pam_faillock.so"])

        if not salida.strip():
            print("[AVISO]: pam_faillock.so no encontrado en el sistema.")
            print("[INFO]: Intentando instalar libpam-modules...")
            ejecutar_comando(["apt-get", "install", "-y", "libpam-modules"], "instalar libpam-modules", paso, mostrarSalida=True)

        else:
            print(f"[CORRECTO]: pam_faillock.so encontrado en {salida.strip()}.")
    else:
        print("[CORRECTO]: pam_faillock disponible.")

    print()
    print("[INFO]: Configurando parámetros de bloqueo de cuentas...")

    configuracion="""#=================================================================
# faillock.conf - bloqueo de cuentas tras intentos fallidos
#=================================================================
# Configurado por fix_mod4
#=================================================================

# Directorio donde se almacenan los registros de fallos por usuario
dir = /var/run/faillock

# Número de intentos fallidos antes de bloquear la cuenta
deny=5

# Tiempo en segundos para desbloquear automáticamente
unlock_time=600

# Ventana de tiempo en segundos para contar intentos
# SI los 5 intentos fallidos ocurren dentro de estos 15 minutos, se bloquea
fail_interval=900

# También bloquea la cuenta root tras intentos fallidos
# NOTA: Si se bloquea root, se puede desbloquear desde consola física
# o esprando unlock_time segundos
even_deny_root=True

# Auditar los intentos fallidos incluso de usuarios existentes
# Esto dificulta la enumeración de usuarios
silent=false

# Tipo de auditoría
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

        lineas=contenido.splitlines()
        nuevasLineas=[]
        insertado=False

        for linea in lineas:
            if "pam_unix.so" in linea and not linea.strip().startswith("#") and not insertado:
                nuevasLineas.append("auth   required                        "
                                    "pam_faillock.so preauth")
                
                nuevasLineas.append(linea)

                nuevasLineas.append("auth   [default=die]                       "
                                    "pam_faillock.so authfail")
                nuevasLineas.append("auth   sufficient                      "
                                    "pam_faillock.so authsucc")

                insertado=True
            else:
                nuevasLineas.append(linea)

        if insertado:
            nuevoContenido="\n".join(nuevasLineas)
            if not nuevoContenido.endswith("\n"):
                nuevoContenido+="\n"

            if escribir_fichero(PAM_COMMON_AUTH, nuevoContenido, permisos=0o644, paso=paso):
                print("[CORRECTO]: 'pam_faillock.so' añadido a common-auth.")
            else:
                registrar_errores(paso, "No se pudo actualizar common-auth.")

    else:
        print("[CORRECTO]: 'pam_faillock.so' ya está configurado en common-auth.")

    contenidoAccount=leer_fichero(PAM_COMMON_ACCOUNT, paso=paso)
    if contenidoAccount is not None:
        if "pam_faillock.so" not in contenidoAccount:
            print("[INFO]: Añadiendo pam_faillock.so a common-account...")

            lineas=contenidoAccount.splitlines()
            insertado=False
            nuevasLineas=[]

            for linea in lineas:
                if "pam_unix.so" in linea and not linea.strip().startswith("#") and not insertado:
                    nuevasLineas.append("account required                        "
                                        "pam_faillock.so")
                    insertado=True
                nuevasLineas.append(linea)


            if insertado:
                nuevoContenido="\n".join(nuevasLineas)

                if not nuevoContenido.endswith("\n"):
                    nuevoContenido+="\n"
                
                if escribir_fichero(PAM_COMMON_ACCOUNT, nuevoContenido, permisos=0o644, paso=paso):
                    print("[CORRECTO]: pam_faillock.so añadido a common-account.")
    else:
        print("[CORRECTO]: pam_faillock.so ya está configurado en common-password.")


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
    
    lineas = contenido.splitlines()
    nuevasLineas=[]
    modificado=False

    for linea in lineas:
        if "pam_unix.so" in linea and not linea.strip().startswith("#"):
            if "remember=" in linea:
                linea=re.sub(r"remember=\d+",
                             f"remember={REMEMBER_VALUE}", linea)
                print(f"[INFO]: Actualizado remember={REMEMBER_VALUE} en pam_unix.so")
                modificado=True
            else:
                linea=linea.rstrip() + f" remember={REMEMBER_VALUE}"
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
        print("[AVISO]: No se encontró 'pam_unix.so' en common-password.")
        print("         Revisa la configuración PAM manualmente.")

    if not os.path.isdir("/etc/security"):
        os.makedirs("/etc/security", exist_ok=True)
    
    if not os.path.isfile(OPASSWD_FILE):
        print("[INFO]: Creando fichero de historial de contraseñas...")
        if escribir_fichero(OPASSWD_FILE, "", permisos=0o600, paso=paso):
            cambiar_permisos(OPASSWD_FILE, propietario=0, grupo=0, paso=paso)
            print(f"[CORRECTO]: {OPASSWD_FILE} creado con permisos 600")
    else:
        permisos=oct(os.stat(OPASSWD_FILE).st_mode)[-3:]
        if permisos!="600":
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
    
    lineas=contenido.splitlines()
    nuevasLineas=[]
    umaskEncontrado=False
    modificado=False

    for linea in lineas:
        if "pam_umask.so" in linea and not linea.strip().startswith("#"):
            umaskEncontrado=True

            if f"umask={UMASK_DESEADO}" not in linea and f"umask=0{UMASK_DESEADO}" not in linea:
                if "umask=" in linea:
                    linea=re.sub(r"umask=\d+", f"umask={UMASK_DESEADO}", linea)
                else:
                    linea=linea.rstrip() + f" umask={UMASK_DESEADO}"
                
                modificado=True
                print(f"[INFO]: Actualizado umask a {UMASK_DESEADO} en pam_umask.so.")
        nuevasLineas.append(linea)
    
    if not umaskEncontrado:
        nuevasLineas.append(f"session optional                        "
                            f"pam_umask.so umask={UMASK_DESEADO}")
        modificado = True
        print(f"[INFO]: Añadido pam_umask.so con umask={UMASK_DESEADO}")

    if modificado:
        nuevoContenido="\n".join(nuevasLineas)
        if not nuevoContenido.endswith("\n"):
            nuevoContenido+="\n"

        if escribir_fichero(PAM_COMMON_SESSION, nuevoContenido, permisos=0o644, paso=paso):
            print("[CORRECTO]: umask configurado en common-session.")
        else:
            registrar_errores("Paso 5", "No se pudo actualizar common-session")
    
    else:
        print(f"[CORRECTO]: umask ya está configurado a {UMASK_DESEADO} en common-session.")

    contenidoLogin=leer_fichero(LOGIN_FILE, paso=paso)
    if contenidoLogin is not None:
        if re.search(r"^UMASK\s+022", contenidoLogin, re.MULTILINE):
            contenidoLogin=re.sub(
                r"^(UMASK\s+)022",
                f"\\g<1>{UMASK_DESEADO}",
                contenidoLogin,
                flags=re.MULTILINE
            )
            escribir_fichero(LOGIN_FILE, contenidoLogin, permisos=0o644, paso=paso)
            print("[CORRECTO]: UMASK actualizado a 027 en /etc/login.defs.")
        elif re.search(r"^UMASK\s+0?27$", contenidoLogin, re.MULTILINE):
            print(f"[CORRECTO]: UMASK ya es 027 en {LOGIN_FILE}.")
        else:
            print("[AVISO]: No se encontró directiva UMASK en /etc/login.defs")

    print()
    print("[INFO]: Con umask 027:")
    print("     - Ficheros nuevos: rw-r----- (640)")
    print("     - Directorios nuevos: rwxr-x--- (750)")
    print("     - 'Otros' no tienen ningún acceso")


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
    
    bloqueoLimites="""
#==============================================================================
# Límites de seguridad - Hardening TFG
#==============================================================================
# Estos límites protegen el servidor contra abuso de recursos.
# Formato: <dominio> <tipo> <recurso> <valor>
# Tipos: soft (advertencia, el usuario puede ampliar) / hard (límite absoluto)
#==============================================================================
# --- Límite de procesos (prevención de fork bombs) ---
# Valores compatibles con entorno gráfico (300+ procesos)
*           soft    nproc           1024
*           hard    nproc           4096

# --- Límite ficheros abiertos ---
# Previene que un usuario agote los descriptores de fichero del sistema
*           soft    nofile          1024
*           hard    nofile          4096

# --- Límite de tamaño de ficheros core (volcado de memoria) ---
# Deshabilitar core dumps previene la fuga de información sensible
# que podría estar en la memoria del proceso
*           soft    core            0
*           hard    core            0

# --- Límite de memoria bloqueada (previene abuso de RAM) ---
# Cantidad máxima de memoria que un proceso puede bloquear en la RAM (KB)
*           soft    memlock         65536
*           hard    memlock         65536

# --- Excepción para root (necesita más recursos para administrar) ---
root        soft    nproc           unlimited
root        hard    nproc           unlimited
root        soft    nofile          65536
root        hard    nofile          65536

#==============================================================================
"""

    if contenidoActual:
        marcaInicio="# Límites de seguridad - Hardening TFG"
        marcaFin="#=============================================================================="
        if marcaInicio in contenidoActual:
            lineas=contenidoActual.splitlines()
            nuevasLineas=[]
            dentroDeBloqueHardening=False
            bloqueTerminado=False

            for linea in lineas:
                if marcaInicio in linea and not bloqueTerminado:
                    dentroDeBloqueHardening=True
                    if nuevasLineas and nuevasLineas[-1].strip()=="":
                        nuevasLineas.pop()
                    continue
                if dentroDeBloqueHardening:
                    if (marcaFin in linea and linea.strip().startswith("#") and "Límites" not in linea):
                        dentroDeBloqueHardening=False
                        bloqueTerminado=True
                    continue
                nuevasLineas.append(linea)
            contenidoActual="\n".join(nuevasLineas)
            print("[INFO]: Bloque de hardening anterior eliminado.")
        nuevoContenido=contenidoActual.rstrip("\n")+"\n"+ bloqueoLimites
    else:
        nuevoContenido=bloqueoLimites

    if escribir_fichero(LIMITS_CONF, nuevoContenido, permisos=0o644, paso=paso):
        print("[CORRECTO]: Límites de recursos configurados en limits.conf.")
    else:
        registrar_errores("Paso 6", "No se pudo escribir limits.conf")
        return
    
    contenidoSession=leer_fichero(PAM_COMMON_SESSION, paso=paso)
    if contenidoSession is not None:
        if "pam_limits.so" not in contenidoSession:
            print("[INFO]: Añadiendo pam_limits.so a common-session...")
            nuevoSession=contenidoSession.rstrip("\n")+"\n"
            nuevoSession+=("session required                            "
                           "pam_limits.so\n")
            if escribir_fichero(PAM_COMMON_SESSION, nuevoSession, permisos=0o644, paso=paso):
                print("[CORRECTO]: pam_limits.so añadido a common-session.")
        else:
            print("[CORRECTO]: pam_limits.so ya presente en common-session.")

    print()
    print("[INFO]: Resumen de límites configurados:")
    print("     - Procesos por usuario: máximo 256 (prevención fork bomb)")
    print("     - Ficheros abiertos: máximo 4096")
    print("     - Core dumps: deshabilitados")
    print("     - Memoria bloqueada: máximo 64 MB")
    print("     - Root: sin límite de procesos ni ficheros.")




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