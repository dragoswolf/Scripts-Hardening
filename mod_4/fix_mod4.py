#!/usr/bin/env python3
#============================================================================================================
# fix_mod4.py -  Script de hardening: PAM (Pluggable Authentication Modules)
#============================================================================================================
# Este script implementa las siguientes medidas de seguridad en Ubuntu Server:
#
#   Paso 1: Eliminar nullok (rechazar contraseñas vacías)
#   Paso 2: Configurar pwquality (complejidad de contraseñas)
#   Paso 3: Configurar faillock (bloqueo tras intentos fallidos)
#   Paso 4: Configurar pwhistory (historial de contraseñas)
#   Paso 5: Configurar umask en PAM (permisos por defecto)
#   Paso 6: Configurar pam_limits (límites de recursos)
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo4_fix.log
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#============================================================================================================


import os
import sys
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__),".."))
from utils import (configurar_logging, 
                   registrar_errores, 
                   comprobar_root,
                   ejecutar_comando, 
                   ejecutar_comando_check, 
                   volver_al_menu,
                   escribir_fichero, 
                   leer_fichero, 
                   cambiar_permisos,
                   print_aviso,
                   print_correcto,
                   print_error,
                   print_info)


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

UMASK_DESEADO="027"
REMEMBER_VALUE=5
LOGIN_FILE="/etc/login.defs"


LOG_FILE="/var/log/hardening/modulo4_fix.log"


CONTENIDO_PWQUALITY="""
#============================================================================================================
# pwquality.conf - Política de calidad de contraseñas
#============================================================================================================
# Configurado por fix_mod4.py
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#============================================================================================================

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


CONTENIDO_FAILLOCK="""
#============================================================================================================
# faillock.conf - bloqueo de cuentas tras intentos fallidos
#============================================================================================================
# Configurado por fix_mod4
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#============================================================================================================

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

BLOQUEO_LIMITES="""
#============================================================================================================
# Límites de seguridad - Hardening TFG
#============================================================================================================
# Estos límites protegen el servidor contra abuso de recursos.
# Formato: <dominio> <tipo> <recurso> <valor>
# Tipos: soft (advertencia, el usuario puede ampliar) / hard (límite absoluto)
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#============================================================================================================
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

#============================================================================================================
"""


def paso1_eliminar_nullok():
    """
    Elimina la opción 'nullok' de pam_unix.so en los ficheros common-auth, common-password
    y common-account.
    """
    print()
    print("="*100)
    print("[PASO 1]: Eliminar nullok (rechazar contraseñas vacías)")
    print("="*100)
    print_info("Elimina la opción 'nullok'. Esto impide que cualquier usuario pueda autenticarse con una contraseña vacía")
    print()

    paso="Paso 1"

    ficherosPam=[PAM_COMMON_ACCOUNT, PAM_COMMON_AUTH, PAM_COMMON_PASSWORD]
    nullokEncontrado=False
    
    for fichero in ficherosPam:
        contenido=leer_fichero(fichero, paso=paso)
        if contenido is None:
            registrar_errores(paso, f"No se pudo leer {fichero}.")
            continue

        # 1a. Buscar lineas que contengan nullok
        lineas=contenido.splitlines()
        modificado=False
        nuevasLineas=[]

        for linea in lineas:
            # 1b. Eliminar nullok de la linea
            if "pam_unix.so" in linea and "nullok" in linea:
                lineaOriginal=linea
                linea=linea.replace(" nullok", "")
                linea=linea.replace("nullok ", "")
                linea=linea.replace("nullok", "")

                print_info(f"{fichero}:")
                print(f"    Antes: {lineaOriginal.strip()}")
                print(f"    Después: {linea.strip()}")

                modificado=True
                nullokEncontrado=True
            nuevasLineas.append(linea)

        # 1c. Guardar modificaciones en el fichero
        if modificado:
            nuevoContenido="\n".join(nuevasLineas)

            if not nuevoContenido.endswith("\n"):
                nuevoContenido+="\n"

            if escribir_fichero(fichero, nuevoContenido, permisos=0o644, paso=paso):
                print_correcto(f"{fichero} actualizado.")
            else:
                registrar_errores(paso, f"No se pudo escribir en {fichero}.")
        else:
            print_correcto(f"{fichero}: Nullok no presente.")
    
    if not nullokEncontrado:
        print()
        print_correcto("Ningún fichero PAM tenía nullok.")


def paso2_configurar_pwquality():
    """
    Instala y configura pam_pwquality para exigir contraseñas robustas.
    """
    print()
    print("="*100)
    print("[PASO 2]: Configurar la complejidad de contraseñas.")
    print("="*100)
    print_info("Instala y configura el módulo pam_pwquality para exigir contraseñas robustas.")
    print()

    paso="Paso 2"

    # 2a. Instalar libpam-pwquality
    rc, salida, _= ejecutar_comando_check(["dpkg", "-s", "libpam-pwquality"])

    if rc!=0:
        print_info("Instalando libpam-pwquality...")
        ejecutar_comando(["apt-get", "install", "-y", "libpam-pwquality"], "instalar libpam-pwquality", paso=paso, mostrarSalida=True)

    else:
        print_correcto("'libpam pwquality' ya está instalado.")

    # 2b. Configurar /etc/security/pwquality.conf
    print()
    print_info("Configurando parámetros de calidad de contraseñas...")

    if escribir_fichero(PWQUALITY_CONF, CONTENIDO_PWQUALITY, permisos=0o644, paso=paso):
        print_correcto("/etc/security/pwquality.conf configurado.")
    else:
        registrar_errores(paso, "No se pudo escribir pwquality.conf")
        return
    
    # 2c. Verificar pam_pwquality.so en common-password
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
            print_correcto("pam_pwquality.so actualizado con retry=3.")
        else:
            print_correcto("pam_pwquality.so ya configurado en common-password.")
    else:
        print_aviso("pam_pwquality.so no está en common-password.")
        print("         Esto se configura automáticamente al instalar")
        print("         libpam-pwquality. Verifica la instalación.")
    

    print()
    print_info("Resumen de la política de contraseñas:")
    print("         - Longitud mínima: 12 caracteres")
    print("         - Al menos 1 dígito, 1 mayúscula, 1 minúscula, 1 especial")
    print("         - Máximo 3 caracteres consecutivos repetidos")
    print("         - Mínimo 5 caracteres diferentes respecto a la anterior")
    print("         - Verificación contra diccionario activada")


def paso3_configurar_faillock():
    """
    Configura pam_faillock para bloquear cuentas tras intentos fallidos.
    """
    print()
    print("="*100)
    print("[PASO 3]: Configurar bloqueos tras intentos fallidos.")
    print("="*100)
    print_info("Configura pam_faillock para bloquear cuentas tras 5 intentos, incluido root. El desbloqueo es automático tras 10 minutos.")
    print()

    paso="Paso 3"    

    # 3a. Verificar que pam_faillock está disponible
    if not os.path.isfile(PAM_FAILLOCK):
        rc, salida,_=ejecutar_comando_check(["find", "/usr/lib", "-name", "pam_faillock.so"])

        if not salida.strip():
            print_aviso("pam_faillock.so no encontrado en el sistema.")
            print_info("Intentando instalar libpam-modules...")
            ejecutar_comando(["apt-get", "install", "-y", "libpam-modules"], "instalar libpam-modules", paso, mostrarSalida=True)

        else:
            print_correcto(f"pam_faillock.so encontrado en {salida.strip()}.")
    else:
        print_correcto("pam_faillock disponible.")

    # 3b. Configurar 7etc/security/faillock.conf
    print()
    print_info("Configurando parámetros de bloqueo de cuentas...")

    if escribir_fichero(FAILLOCK_CONF, CONTENIDO_FAILLOCK, permisos=0o644, paso=paso):
        print_correcto("/etc/security/faillock.conf configurado.")
    else:
        registrar_errores(paso, "no se pudo escribir faillock.conf")
        return
    
    # 3c. Configurar faillock en common-auth
    contenido= leer_fichero(PAM_COMMON_AUTH, paso=paso)
    if contenido is None:
        registrar_errores(paso, f"No se pudo leer {PAM_COMMON_AUTH}")
        return
    
    if "pam_faillock.so" not in contenido:
        print_info("Añadiendo pam_faillock.so a common-auth...")

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
                print_correcto("'pam_faillock.so' añadido a common-auth.")
            else:
                registrar_errores(paso, "No se pudo actualizar common-auth.")

    else:
        print_correcto("'pam_faillock.so' ya está configurado en common-auth.")

    # 3d. Configurar faillock en common-account
    contenidoAccount=leer_fichero(PAM_COMMON_ACCOUNT, paso=paso)
    if contenidoAccount is not None:
        if "pam_faillock.so" not in contenidoAccount:
            print_info("Añadiendo pam_faillock.so a common-account...")

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
                    print_correcto("pam_faillock.so añadido a common-account.")
    else:
        print_correcto("pam_faillock.so ya está configurado en common-password.")

    print()
    print_info("Resumen de la política de bloqueo:")
    print_info("    - Bloqueo tras 5 intentos fallidos.")
    print_info("    - Desbloqueo automático tras 10 minutos.")
    print_info("    - Ventana de 15 minutos para contar intentos.")
    print_info("    - Root también se bloquea.")
    print()
    print_info("Comandos útiles:")
    print_info("    faillock --user <usuario>           -> Ver el estado del usuario")
    print_info("    faillock --user <usuario> --reset   -> Desbloquear el usuario")


def paso4_configurar_pwhistory():
    """
    Configura pam_pwhistory.so en common-password para impedir 
    la reutilización de las últimascinco contraseñas.
    """
    print()
    print("="*100)
    print("[PASO 4]: Configurar historial de contraseñas")
    print("="*100)
    print_info("Configura pam_pwhistory. para impedir la reutilización de las 5 últimas contraseñas.\n" \
    "       Asegura que pam_unix.so use use_authtok y yescrypt como algoritmo de hashing seguro.")
    print()

    paso="Paso 4"

    contenido=leer_fichero(PAM_COMMON_PASSWORD, paso=paso)
    if contenido is None:
        registrar_errores("Paso 4", f"No se pudo leer {PAM_COMMON_PASSWORD}.")
        return
    
    lineas = contenido.splitlines()
    nuevasLineas=[]
    modificado=False
    pwhistoryExiste=False

    # 4a. Comprobar si pam_pwhistory.so ya está configurado.
    for linea in lineas:
        if "pam_pwhistory.so" in linea and not linea.strip().startswith("#"):
            pwhistoryExiste=True
            break


    for linea in lineas:
        limpia=linea.strip()

        if ("pam_unix.so" in linea and not linea.strip().startswith("#") and limpia.startswith("password")):
            # 4b. Verificar la existencia de use_authtok
            if "use_authtok" not in linea:
                linea=linea.rstrip() + " use_authtok"
                print_info("Añadido use_authtok a pam_unix.so")
                modificado=True
            
            # 4c. Verificar el uso de un algoritmo de hashing seguro
            algoritmosInseguros=["md5", "bigcrypt", "sha256", "blowfish"]
            tieneHashSeguro=("yescrypt" in linea or "sha512" in linea)

            if not tieneHashSeguro:
                # Quitamos algoritmos inseguros si los hay
                for algo in algoritmosInseguros:
                    if algo in linea:
                        linea = linea.replace(f" {algo}", "")
                        print_correcto(f"Algoritmo inseguro {algo} eliminado de 'pam_unix.so'.")
                linea=linea.rstrip()+" yescrypt"
                print_info("Añadido yescrypt a pam_unix.so")
                modificado=True

            # 4d. Añadir pam_pwhistory.so antes de pam_unix.so
            if not pwhistoryExiste:
                lineasPwhistory=(f"password\trequired\t\t\tpam_pwhistory.so remember={REMEMBER_VALUE} use_authtok enforce_for_root")
                nuevasLineas.append(lineasPwhistory)
                print_info(f"Añadido pam_pwhistory.so con remember={REMEMBER_VALUE} antes de pam_unix.so")
                pwhistoryExiste=True
                modificado=True
        nuevasLineas.append(linea)


    # 4e. Guardar modificaciones
    if modificado:
        nuevoContenido="\n".join(nuevasLineas)
        if not nuevoContenido.endswith("\n"):
            nuevoContenido+="\n"
        if escribir_fichero(PAM_COMMON_PASSWORD, nuevoContenido, permisos=0o644, paso=paso):
            print_correcto(f"Historial de contraseñas configurado. (recordará las últimas {REMEMBER_VALUE}).")
        else:
            registrar_errores("Paso 4", "No se pudo actualizar common-password")

    else:
        if pwhistoryExiste:
            print_correcto("'pam_pwhistory' ya está configurado.")
        else:
            print_aviso("No se encontró 'pam_unix.so' en common-password.")
            print("         Revisa la configuración PAM manualmente.")

    # 4f. Crear directorio para el historial de contraseñas si no existe
    if not os.path.isdir("/etc/security"):
        os.makedirs("/etc/security", exist_ok=True)
    
    # 4g. Crear fichero de historial de contraseñas si no existe
    if not os.path.isfile(OPASSWD_FILE):
        print_info("Creando fichero de historial de contraseñas...")
        if escribir_fichero(OPASSWD_FILE, "", permisos=0o600, paso=paso):
            cambiar_permisos(OPASSWD_FILE, propietario=0, grupo=0, paso=paso)
            print_correcto(f"{OPASSWD_FILE} creado con permisos 600")
    else:
        cambiar_permisos(OPASSWD_FILE, permisos=0o600, paso=paso)



def paso5_configurar_umask():
    """
    COnfigura el umask a 027 en PAm para que los ficheros y directorios creados por los usuarios
    no sean legibles por 'otros'
    """
    print()
    print("="*100)
    print("[PASO 5]: Configurar umask en PAM (permisos por defecto)")
    print("="*100)
    print_info("Configura umask 027 en PAM (common-session) y login.defs.\n" \
    "       Con esto se logra que los ficheros y directorios creados por los usuarios no sean legibles por 'otros'.")
    print()

    paso="Paso 5"

    # 5a. Verificar/configurar umask en common-session
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
                print_info(f"Actualizado umask a {UMASK_DESEADO} en pam_umask.so.")
        nuevasLineas.append(linea)
    
    if not umaskEncontrado:
        nuevasLineas.append(f"session optional                        "
                            f"pam_umask.so umask={UMASK_DESEADO}")
        modificado = True
        print_info(f"Añadido pam_umask.so con umask={UMASK_DESEADO}")

    if modificado:
        nuevoContenido="\n".join(nuevasLineas)
        if not nuevoContenido.endswith("\n"):
            nuevoContenido+="\n"

        if escribir_fichero(PAM_COMMON_SESSION, nuevoContenido, permisos=0o644, paso=paso):
            print_correcto("umask configurado en common-session.")
        else:
            registrar_errores("Paso 5", "No se pudo actualizar common-session")
    
    else:
        print_correcto(f"umask ya está configurado a {UMASK_DESEADO} en common-session.")

    # 5b. Configurar UMASK en /etc/login.defs como respaldo
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
            print_correcto("UMASK actualizado a 027 en /etc/login.defs.")
        elif re.search(r"^UMASK\s+0?27$", contenidoLogin, re.MULTILINE):
            print_correcto(f"UMASK ya es 027 en {LOGIN_FILE}.")
        else:
            print_aviso("No se encontró directiva UMASK en /etc/login.defs")

    print()
    print_info("Con umask 027:")
    print_info("     - Ficheros nuevos: rw-r----- (640)")
    print_info("     - Directorios nuevos: rwxr-x--- (750)")
    print_info("     - 'Otros' no tienen ningún acceso")
    print()


def paso6_configurar_limits():
    """
    Configura límites de recursos en /etc/security/limits.conf para prevenir abuso de recursos
    y fork bombs
    """
    print()
    print("="*100)
    print("[PASO 6]: Configurar límites de recursos")
    print("="*100)
    print_info("Configura límites de recursos en /etc/security/limits.conf. Con esto se pretende prevenir el abuso de recursos y fork bombs.")
    print()

    paso="Paso 6"

    # 6a. Escribir bloque de límites en limits.conf
    contenidoActual=leer_fichero(LIMITS_CONF, paso=paso)

    if contenidoActual and "# Hardening TFG" in contenidoActual:
        print_correcto("Los límites de hardening ya están configurados.")
        print_info("Para modificarlos, edita /etc/security/limits.conf")
        return
    

    if contenidoActual:
        marcaHardening="# Límites de seguridad - Hardening TFG"
        marcaEndOfFile="# End of file"
        if marcaHardening in contenidoActual:
            indice=contenidoActual.index(marcaEndOfFile)
            contenidoActual=contenidoActual[:indice+len(marcaEndOfFile)]
            print_info("Bloque de hardening anterior eliminado.")
        nuevoContenido=contenidoActual.rstrip("\n")+"\n"+ BLOQUEO_LIMITES
    else:
        nuevoContenido=BLOQUEO_LIMITES

    if escribir_fichero(LIMITS_CONF, nuevoContenido, permisos=0o644, paso=paso):
        print_correcto("Límites de recursos configurados en limits.conf.")
    else:
        registrar_errores("Paso 6", "No se pudo escribir limits.conf")
        return
    
    # 6b. Verificar pam_limits.so en common-session.
    contenidoSession=leer_fichero(PAM_COMMON_SESSION, paso=paso)
    if contenidoSession is not None:
        if "pam_limits.so" not in contenidoSession:
            print_info("Añadiendo pam_limits.so a common-session...")
            nuevoSession=contenidoSession.rstrip("\n")+"\n"
            nuevoSession+=("session required                            "
                           "pam_limits.so\n")
            if escribir_fichero(PAM_COMMON_SESSION, nuevoSession, permisos=0o644, paso=paso):
                print_correcto("pam_limits.so añadido a common-session.")
        else:
            print_correcto("pam_limits.so ya presente en common-session.")

    print()
    print_info("Resumen de límites configurados:")
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
                paso4_configurar_pwhistory()
                volver_al_menu()
            case "5":
                paso5_configurar_umask()
                volver_al_menu()
            case "6":
                paso6_configurar_limits()
                volver_al_menu()
            case "q":
                print_info("Saliendo del script.")
                sys.exit(0)
            case _:
                print_error("Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()