#!/usr/bin/env python3

import os
import sys
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__),".."))
from utils import (configurar_logging, registrar_errores, comprobar_root,
                   ejecutar_comando, volver_al_menu, escribir_fichero, leer_fichero)



PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"
LOGIN_DEFS_FILE="/etc/login.defs"
SUDOERS_DIR="/etc/sudoers.d"
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
LOG_FILE="/var/log/hardening/modulo2_fix.log"

GRUPOS_SENSIBLES=["sudo", "adm", "shadow", "disk", "docker"]

CONTENIDO_SUDO_HARDENING=(
    "# Configuración de hardening para sudo\n"
    "# Generado por fix_mod2.py\n"
    "#========================================================"
    "\n"
)




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
        os_chmod(PASSWD_FILE, 644)
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
                subprocess.run("usermod -s /usr/sbin/nologin "+nombre)
        else:
            print("[INFO]: No se realizaron cambios.")



def paso2_auditar_grupos():
    print()
    print("="*100)
    print("[PASO 2]: Auditar grupos y pertenencia")
    print("="*100)
    print()

    for grupo in GRUPOS_SENSIBLES:
        resultado=subprocess.run(["getent", "group", grupo], capture_output=True, text=True)

        if resultado.returncode:
            campos=resultado.stdout.split(":")
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
            ejecutar_comando(["gpasswd", "-d",  usuario, grupo])
            print(f"[CORRECTO]: Usuario '{usuario}' eliminando del grupo '{grupo}'.")
    else:
        print("[INFO]: No se realizaron cambios.")






