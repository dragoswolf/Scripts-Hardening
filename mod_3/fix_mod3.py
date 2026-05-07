#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__),".."))
from utils import (configurar_logging, registrar_errores, comprobar_root,
                   ejecutar_comando, volver_al_menu, escribir_fichero, leer_fichero, cambiar_permisos,
                   ejecutar_comando_check)



PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"
LOGIN_DEFS_FILE="/etc/login.defs"
SUDOERS_DIR="/etc/sudoers.d"
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
LOG_FILE="/var/log/hardening/modulo3_fix.log"

GRUPOS_SENSIBLES=["sudo", "adm", "shadow", "disk", "docker"]

CONTENIDO_SUDO_HARDENING=(
    "# Configuración de hardening para sudo\n"
    "# Generado por fix_mod2.py\n"
    "#========================================================\n"
    "\n"
    "# Registrar todos los comandos ejecutados con sudo\n"
    'Defaults   logfile="/var/log/sudo.log"\n'
    "Defaults   log_input, log_output\n"
    "\n"
    "# Timeout de 5 minutos (por defecto es 15)\n"
    "Defaults   timestamp_timeout=5\n"
    "\n"
    "# Máximo 3 intentos de contraseña\n"
    "Defaults   passwd_tries=3\n"
    "\n"
    "# Mostrar aviso al usar sudo\n"
    'Defaults   lecture="always"\n'
    "\n"
    "# Requerir TTY para usar sudo\n"
    "Defaults   requiretty\n"
)

PARAMETROS_LOGIN_DEFS={
    "PASS_MAX_DAYS": "90",
    "PASS_MIN_DAYS": "7",
    "PASS_WARN_AGE": "14",
    "PASS_MIN_LEN": "12",
    "ENCRYPT_METHOD": "yescrypt",
    "UMASK": "27"
}




def paso1_auditar_passwd():
    print()
    print("="*100)
    print("[PASO 1]: Auditar /etc/passwd")
    print("="*100)
    print()

    contenido=leer_fichero(PASSWD_FILE, paso="Paso 1")
    if contenido is None:
        print("[ERROR]: No se puede leer /etc/passwd.")
        return
    
    permisos=oct(os.stat(PASSWD_FILE).st_mode)[-3:]
    if permisos !="644":
        print(f"[INFO]: Corrigiendo permisos de {PASSWD_FILE} de {permisos} a 644...")
        cambiar_permisos(PASSWD_FILE, permisos=0o644, paso="Paso 1")
        print("[CORRECTO]: Permisos corregidos.")
    else:
        print(f"[CORRECTO]: Permisos de {PASSWD_FILE} correctos (644).")

    shellsInteractivas=["bin/bash", "/bin/sh", "/bin/zsh", "/bin/ksh", "/bin/csh", "/bin/fish"]
    cuentasServicio=[]

    for linea in contenido.split("\n"):
        campos=linea.split(":")

        if len(campos) > 1:
            nombre=campos
            uid=int(campos[1])
            shell=campos[2]
            
            if uid<1000 and shell in shellsInteractivas:
                cuentasServicio.append((nombre, uid, shell))

    if not cuentasServicio:
        print("[CORRECTO]: Ninguan cuenta de servicio tiene shell interactiva.")
    else:
        print(f"\n[AVISO]: Se encontraron {len(cuentasServicio)} cuenta(s) de servicio con shell interactiva:")
        for nombre, uid, shell in cuentasServicio:
            print(f"[CORRECTO]: Shell de '{nombre}' cambiada a /usr/sbin/nologin.")

        print()
        respuesta=input("¿Cambiar sus shells a /usr/sbin/nologin? (s/n): ").strip().lower()
        if respuesta=="s":
            for nombre, uid, shell in cuentasServicio:
                ejecutar_comando(["usermod", "-s", "/usr/sbin/nologin", nombre], f"cambiar shell de {nombre}", "Paso 1")
                print(f"[OK], Shell de '{nombre}' cambiada a /usr/sbin/nologin.")
        else:
            print("[INFO]: No se realizaron cambios.")



def paso2_auditar_grupos():
    print()
    print("="*100)
    print("[PASO 2]: Auditar grupos y pertenencia")
    print("="*100)
    print()

    for grupo in GRUPOS_SENSIBLES:
        rc, salida, _ =ejecutar_comando_check(["getent", "group", grupo])

        if rc==0:
            campos=salida.stdout.split(":")
            miembros=campos[1]
            print(f"{grupo}: {miembros}")
        else:
            print(f"{grupo}: No existe")
        
    print()
    print("[INFO]: Si necesitas eliminar un usuario de un grupo:")
    print("         sudo gpasswd -d <usuario> <grupo>")
    print()

    respuesta=input("¿Quieres eliminar algún usuario de un grupo? (s/n): ").strip().lower

    if respuesta=="s" or "S":
        usuario=input("Nombre del usuario: ")
        grupo=input("Nombre del grupo: ")

        if usuario and grupo:
            ejecutar_comando(["gpasswd", "-d",  usuario, grupo], f"eliminar '{usuario}' del grupo '{grupo}'", "Paso 2")
            print(f"[CORRECTO]: Usuario '{usuario}' eliminando del grupo '{grupo}'.")
    else:
        print("[INFO]: No se realizaron cambios.")


def paso3_configurar_sudo():
    print()
    print("="*100)
    print("[PASO 3]: Configurar sudo")
    print("="*100)
    print()

    rutaHardening=os.path.join("hardening", SUDOERS_DIR)

    if os.path.isfile(rutaHardening):
        print(f"[INFO]: Ya existe {rutaHardening}.")

        contenidoActual=leer_fichero(rutaHardening, paso="Paso 3")

        if contenidoActual:
            print("[INFO]: Contenido actual:")
            print(contenidoActual)
        
        respuesta=input("¿Sobreescribir con la configuración recomendada? (s/n)").strip().lower()

        if respuesta=="s":
            print("[INFO]: No se realizaron cambios")
            return
        
    print("[INFO]: Creando configuración de hardening para sudo...")

    exito=escribir_fichero(rutaHardening, CONTENIDO_SUDO_HARDENING, permisos=440, paso="Paso 3")

    if exito:
        print(f"[CORRECTO]: Configuración de hardening creada en {rutaHardening}.")

        ejecutar_comando(["visudo", "-c", "-f", "/etc/sudoers"], "validar configuraciónd de sudoers", "Paso 3")
        print("[CORRECTO]: Configuración de sudoers validada.")
    else:
        print("[ERROR]: No se pudo crear el fichero de hardening.")

    print()
    rc, salida, _=ejecutar_comando_check(["grep", "-r", "NOPASSWD", "/etc/sudoers", SUDOERS_DIR])

    if rc!=0:
        print("[AVISO]: Se encontraron reglas NOPASSWD activas:")
        print(salida)
        print("[AVISO]: Revisa si son necesarias.")
    else:
        print("[CORRECTO]: No hay reglas NOPASSWD.")


def paso4_proteger_shadow():
    print()
    print("="*100)
    print("[PASO 4]: Proteger Shadow")
    print("="*100)
    print()

    if not os.path.isfile(SHADOW_FILE):
        registrar_errores("Paso 4", f"No se encontró {SHADOW_FILE}.")
        return
    
    permisos=oct(os.stat(SHADOW_FILE).st_mode)
    if permisos not in ["640", "600"]:
        print(f"[INFO]: Corrigiendo permisos de {SHADOW_FILE} de {permisos} a 640...")
        cambiar_permisos(SHADOW_FILE, permisos=0o640, paso="Paso 4")
        print("[CORRECTO]: Permisos corregidos a 640.")
    else:
        print(f"[CORRECTO]: Permisos de {SHADOW_FILE} correctos ({permisos}).")

    infoStat=os.stat(SHADOW_FILE)
    
    if infoStat.st_uid !=0:
        print(f"[INFO]: Corrigiendo propietario de {SHADOW_FILE}...")
        cambiar_permisos(SHADOW_FILE, propietario=0, paso="Paso 4")
        print("[CORRECTO]: Propietario corregido a root.")
    else:
        print(f"[CORRECTO]: {SHADOW_FILE} ya es propiedad de root.")

    contenido=leer_fichero(SHADOW_FILE, paso="Paso 4")

    for linea in contenido.splitlines():
        campos=linea.split(":")
        nombre=campos
        hashCampo=campos[5]

        if "$1$" in hashCampo or "$5$" in hashCampo:
            print(f"[AVISO]: Usuario {nombre} usa un algoritmo débil.")
            print(f"[INFO]: Bloqueando contraseña de {nombre} por seguridad...")
            ejecutar_comando(["usermod", "-p", "!", nombre], f"bloqueando contraseña de {nombre}", "Paso 4")

def paso5_configurar_login_defs():
    print()
    print("="*100)
    print("[PASO 4]: Proteger Shadow")
    print("="*100)
    print()

    contenido=leer_fichero(LOGIN_DEFS_FILE, paso="Paso 5")
    if contenido is None:
        return
    
    lineasModificadas=contenido.split("\n")
    cambiosRealizados=0

    for parametro, valorNuevo in PARAMETROS_LOGIN_DEFS.items():
        encontrado=False

        for i in range(len(lineasModificadas)):
            if parametro in lineasModificadas[i]:
                lineasModificadas[i]=f"{parametro}\t\t{valorNuevo}"
                print(f"[CORRECTO]: {parametro} actualizado a {valorNuevo}.")
                cambiosRealizados+=1
                encontrado=True

        if not encontrado:
            lineasModificadas.append(f"{parametro}\t\t{valorNuevo}")
            print(f"[CORRECTO]: {parametro}: añadido con valor {valorNuevo}")
            cambiosRealizados+=1


    if cambiosRealizados>0:
        nuevoContenido="\n".join(lineasModificadas)

        exito=escribir_fichero(LOGIN_DEFS_FILE, nuevoContenido, permisos=0o600, paso="Paso 5")

        if exito:
            print(f"[CORRECTO]: Parámetros actualizados en {LOGIN_DEFS_FILE}.")
        else:
            print(f"[ERROR]: No se puede escribir en {LOGIN_DEFS_FILE}.")

    
def paso6_envejecimiento_contrasenas():
    print()
    print("="*100)
    print("[PASO 6]: Envejecimiento de contraseñas en usuarios existentes.")
    print("="*100)
    print()

    contenido=leer_fichero(PASSWD_FILE, paso="Paso 6")

    if contenido is None:
        return
    
    usuariosHumanos=[]

    for linea in contenido.splitlines():
        campos=linea.split(":")

        identificador=int(campos[4])

        if identificador<1000:
            usuariosHumanos.append(campos)

    if not usuariosHumanos:
        print("[INFO]: No se encontraron usuarios.")
        return
    
    print(f"[INFO]: Se aplicará la política a {len(usuariosHumanos)} usuario(s):")

    for usuario in usuariosHumanos:
        ejecutar_comando(["chage", "-m", "90", "-M", "7", "-W", "14", usuario], f"aplicar política de contraseñas a {usuario}", paso="Paso 6")

        print(f"[CORRECTO]: Política aplicada a {usuario}")


def paso7_cuentas_sin_contrasena():
    print()
    print("="*100)
    print("[PASO 7]: Deshabilitar cuentas sin contraseña.")
    print("="*100)
    print()

    contenido=leer_fichero(SHADOW_FILE, paso="Paso 7")
    if contenido is None:
        return
    
    cuentasSinPassword=[]

    for linea in contenido.strip().splitlines():
        campos=linea.split(":")

        hashPass=campos[5]
        if hashPass=="":
            cuentasSinPassword.append(campos)

    if not cuentasSinPassword:
        print("[CORRECTO]: No hay cuentas con contraseña vacía.")
    else:
        print(f"[AVISO]: Se encontraron cuentas sin contraseña.")
        for cuenta in cuentasSinPassword:
            ejecutar_comando(["passwd", "-l", cuenta], f"bloqueando cuenta {cuenta}", paso="Paso 7")
            print(f"[CORRECTO]: Cuenta '{cuenta}' bloqueada con éxito.")
    
    print()
    contenidoSsh=leer_fichero(SSHD_CONFIG_FILE, paso="Paso 7")
    if contenidoSsh is not None:
        lineaEncontrada=False
        lineaSsh=contenidoSsh.splitlines()

        for i in range(len(lineaSsh)):
            if "PermitEmptyPasswords" in lineaSsh[i] and "#" not in lineaSsh[i]:
                lineaEncontrada=True
                lineaSsh[i]="PermitEmptyPasswords=no"
                print("[CORRECTO]: SSH: PermitEmptyPasswords cambiado a no.")
                break

        if not lineaEncontrada:
            lineaSsh.append("PermitEmptyPasswords=no")

        nuevoContenido="\n".join(lineaSsh)

        escribir_fichero(SSHD_CONFIG_FILE, nuevoContenido, permisos=0o600, paso="Paso 7")
        ejecutar_comando(["systemctl", "reload", "sshd"], "recargar sshd", "Paso 7")
        print("[CORRECTO]: SSH: PermitEmptyPasswords = no (configurado).")


def paso8_bloquear_uid0():
    print()
    print("="*100)
    print("[PASO 8]: Buscar y bloquear cuentas no-root con UID 0.")
    print("="*100)
    print()

    contenido=leer_fichero(PASSWD_FILE, paso="Paso 8")
    if contenido is None:
        return
    
    cuentasUid0=[]

    lineas=contenido.strip().splitlines()

    for linea in lineas:
        if linea:
            campos=linea.split(":")
            usuario=campos
            uid=campos[5]

            if "0" in uid:
                cuentasUid0.append(usuario)

    if not cuentasUid0:
        print("[CORRECTO]: Solo 'root' tiene UID 0. No hay cuentas sospechosas.")
    else:
        print(f"[AVISO]: Se encontraron {len(cuentasUid0)} cuenta(s) no-root con UID 0:")
        
        for cuenta in cuentasUid0:
            print(f"        - {cuenta}")
        print()
        print("[INFO]: Bloqueando cuentas sospechosas...")

        for cuenta in cuentasUid0:
            ejecutar_comando(["usermod", "-L", cuenta], f"bloquear cuenta {cuenta}", "Paso 8")
            ejecutar_comando(["usermod", "-s", "/usr/sbin/nologin", cuenta], f"cambiar shell de {cuenta}", "Paso 8")
            print(f"[CORRECTO]: Cuenta '{cuenta}' bloqueada y shell cambiada a nologin.")

    
def paso9_bloqueo_inactivas():
    print()
    print("="*100)
    print("[PASO 9]: Bloqueo automático de cuentas inactivas.")
    print("="*100)
    print()

    print("[INFO]: Configurando INACTIVE=30 para nuevas cuentas...")

    ejecutar_comando(["useradd", "-D", "-e", "30"], "configurar INACTIVE=30", "Paso 9")

    print("[CORRECTO]: INACTIVE=30 configurado para nuevas cuentas.")
    print()

    contenido=leer_fichero(PASSWD_FILE, paso="Paso 9")
    if contenido is None:
        return
    
    usuariosAfectados=[]
    
    for linea in contenido.strip().splitlines():
        campos=linea.split(":")
        
        if len(campos)>=3:
            uid=int(campos[2])
            if uid<1000:
                usuariosAfectados.append(campos)

    if usuariosAfectados:
        print(f"[INFO]: Aplicando INACTIVE=30 a {len(usuariosAfectados)} usuario(s)...")

        for usuario in usuariosAfectados:
            ejecutar_comando(["chage", "-E", "30", usuario], f"configurar inactividad para {usuario}", "Paso 9")
            print(f"[CORRECTO]: INACTIVE=30 aplicado a: {usuario}")

def paso10_restringir_root():
    print()
    print("="*100)
    print("[PASO 10]: Restringir acceso root directo.")
    print("="*100)
    print()

    rc, salida, _=ejecutar_comando_check(["getent", "group", "sudo"])
    if rc==0:
        if "sudo" in salida:
            print("[CORRECTO]: El grupo sudo existe y está listo.")
        else:
            print("[AVISO]: No se puede bloquear root sin tener acceso sudo alternativo.")
            return
    else:
        print("[ERROR]: No se pudo verificar el grupo sudo.")
        return
    
    print()

    rcRoot, salidaRoot, _=ejecutar_comando_check(["passwd", "-S", "root"])
    if rcRoot==0:
        estado=salidaRoot.strip().split()

        if estado=="L":
            print("[CORRECTO]: Contraseña de root ya está bloqueada.")
        else:
            respuesta=input("¿Bloquear la contraseña de root? (s/n): ").strip().lower()
            if respuesta=="s":
                ejecutar_comando(["passwd", "-d", "root"], "bloquear contraseña de root", "Paso 10")
                print("[CORRECTO]: Contraseña de root bloqueada.")
    
    print()

    contenidoSsh=leer_fichero(SSHD_CONFIG_FILE, paso="Paso 10")

    if contenidoSsh is not None:
        lineaSsh=contenidoSsh.splitlines()
        lineaSsh.append("PermitRootLogin no")

        escribir_fichero(SSHD_CONFIG_FILE, "\n".join(lineaSsh)+"\n", permisos=0o777, paso="Paso 10")
        ejecutar_comando(["systemctl", "reload", "sshd"], "recargar sshd", "Paso 10")
        print("[CORRECTO]: SSH: PermitRootLogin = no (configurado y sshd recargado).")


def mostar_menu():
    print()
    print("="*100)
    print("Hardening: Usuarios y Grupos")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Auditar /etc/passwd")
    print("     2. Auditar grupos y pertenencia")
    print("     3. Configurar sudo de forma segura")
    print("     4. Proteger /etc/shadow")
    print("     5. Configurar /etc/login.defs")
    print("     6. Envejecimiento de contraseñas (usuarios existentes)")
    print("     7. Deshabilitar cuentas sin contraseña")
    print("     8. Bloquear usuarios no-root con UID 0")
    print("     9. Bloqueo automático de cuentas inactivas")
    print("     10. Restringir acceso root directo")
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
                paso1_auditar_passwd()
                volver_al_menu()
            case "2":
                paso2_auditar_grupos()
                volver_al_menu()
            case "3":
                paso3_configurar_sudo()
                volver_al_menu()
            case "4":
                paso4_proteger_shadow()
                volver_al_menu()
            case "5":
                paso5_configurar_login_defs()
                volver_al_menu()
            case "6":
                paso6_envejecimiento_contrasenas()
                volver_al_menu()
            case "7":
                paso7_cuentas_sin_contrasena()
                volver_al_menu() 
            case "8":
                paso8_bloquear_uid0()
                volver_al_menu()
            case "9":
                paso9_bloqueo_inactivas()
                volver_al_menu()
            case "10":
                paso10_restringir_root()
                volver_al_menu()
            case "q":
                print("\n[INFO]: Saliendo del script.")
                sys.exit(0)
            case _:
                print("[ERROR]: Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()