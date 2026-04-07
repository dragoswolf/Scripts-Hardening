#!/usr/bin/env python3

import os
import sys
import subprocess
import getpass
import logging
from datetime import datetime


#Ficheros de conf y directorios importantes
GRUB_CUSTOM_FILE="/etc/grub.d/40_custom"
GRUB_CFG_FILE= "/boot/grub/grub.cfg"
USB_MODPROBE_FILE="/etc/modprobe.d/usb-storage.conf"
LOG_DIR="/var/log/hardening"
LOG_FILE="/var/log/hardening/modulo1_fix.log"

#variables extra para chequeo
totalChecks=0
checksOk=0
checksFail=0
checksWarn=0


#FUNCIONES DE APOYO
#=========================================================================================================
#Función para la configuración logging
def configurar_logging():
    if not os.path.isdir(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)

    #formato de logging
    logging.basicConfig(filename=LOG_FILE, 
                        level=logging.ERROR, 
                        format="[%(asctime)s] %(levelname)s: %(message)s", 
                        datefmt="%Y-%m-%d %H:%M:%S"
                        )
    
#función para registrar errores en los logs
def registrar_errores(paso, mensaje):
    textoLog=f"[{paso}] {mensaje}"
    logging.error(textoLog)
    print(f"[ERROR]: {mensaje}")

#función para comprobar el uso de sudo
def comrpobar_root():
    if os.geteuid()!=0:
        print("[ERROR]: Este script ha de ejecutarse como root.")
        print("         Ejecuta: sudo python3 fix_mod1.py")
        sys.exit(1)

def resultado_fail(mensaje, paso="General"):
    global totalChecks, checksFail
    totalChecks +=1
    checksFail +=1

    #imprimir en rojo el fallo y luego resetear el color. Esta logica se va a usar en todos los resultados
    print(f"    \033[91m[FALLO]:\033[0m {mensaje}")
    registrar_errores(paso, mensaje)

def resultado_warn(mensaje):
    global totalChecks, checksWarn
    totalChecks+=1
    checksWarn+=1

    print(f"    \033[93m[AVISO]:\033[0m {mensaje}")

def resultado_ok(mensaje):
    global totalChecks, checksOk
    totalChecks+=1
    checksOk+=1

    print(f"    \033[92m[CORRECTO]:\033[0m {mensaje}")

def leer_fichero(ruta, paso="General"):
    try:
        with open(ruta,"r") as f:
            return f.read()
    except FileNotFoundError:
        return None
    except PermissionError:
        registrar_errores(paso, f"Sin permisos para leer {ruta}")
        return None
    
#=========================================================================================================


#verificamos el paso 1
# Leemos primero el archivo 40_custom
# buscamos si tenemos superusers y password_pbkdf2
# leemos el fichero de configuración del GRUB
# buscamos si tenemos superusers y password_pbkdf2
# ambos ficheros tienen que tener la configuración
def verificar_paso1():
    print()
    print("="*70)
    print("PASO 1: Verificación de la protección del gestor de arranque GRUB.")
    print("="*70)

    contenidoCustom=leer_fichero(GRUB_CUSTOM_FILE, paso="Paso 1")
    if contenidoCustom is None:
        resultado_fail(
            f"No se encontró {GRUB_CUSTOM_FILE}. GRUB no tiene configuración de contraseña", 
            paso="Paso 1")
        return
    
    #si el archivos existe
    if "set superusers" in contenidoCustom:
        for linea in contenidoCustom.splitlines():
            if "set superusers" in linea:
                resultado_ok(f"Superusuario GRUB configurado: {linea.strip()}")
                break
    else:
        resultado_fail(f"No se encontró la directiva 'set superusers' en {GRUB_CUSTOM_FILE}.", paso="Paso 1")

    if "password_pbkdf2" in contenidoCustom:
        resultado_ok(f"Hash PBKDF2 de contraseña GRUB presente en {GRUB_CUSTOM_FILE}.")
    else:
        resultado_fail(f"No se encontró hash 'password_pbkdf2' en {GRUB_CUSTOM_FILE}.", paso="Paso 1")

    
    #leemos el archivo de configuración y realizamos verificación cruzada
    contenidoCfg=leer_fichero(GRUB_CFG_FILE, paso="Paso 1")
    if contenidoCfg is not None:
        if "superusers" in contenidoCfg and "password_pbkdf2" in contenidoCfg:
            resultado_ok("Protección de GRUB presente en grub.cfg. 'update-grup' aplicado.")
        else:
            resultado_warn(f"{GRUB_CUSTOM_FILE} tiene configuración pero {GRUB_CFG_FILE} no la refleja.")
            resultado_warn("Ejecuta 'sudo update-grub' para aplicar los cambios.")
    else:
        resultado_warn(f"No se puede leer {GRUB_CFG_FILE} para la verificación cruzada")
    