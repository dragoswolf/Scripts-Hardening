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
def comprobar_root():
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
        print(f"Fichero {ruta} no encontrado.")
        return None
    except PermissionError:
        registrar_errores(paso, f"Sin permisos para leer {ruta}")
        return None
    
def mostrar_resumen():
    print()
    print("="*100)
    print("RESUMEN DE VERIFICACIÓN DE MÓDULO 1 - SEGURIDAD EN ACCESO AL HARDWARE")
    print("="*100)
    print()

    print(f"    Total de verificaciones: {totalChecks}")
    print(f"    \033[92mCorrectamente configurado: {checksOk}\033[0m")
    print(f"    \033[91mConfiguraciones fallidas: {checksFail}\033[0m")    
    print(f"    \033[93mAdvertencias: {checksWarn}\033[0m")
    print()

    if checksFail==0 and checksWarn==0:
        print("="*100)
        print("    \033[92mTODAS LAS CONFIGURACIONES SON CORRECTAS\033[0m")
        print("="*100)
    elif checksFail==0:
        print("="*100)
        print("    \033[93mEXISTEN ADVERTENCIAS. REVISARLAS.\033[0m")
        print("="*100)
    else:
        print("="*100)
        print("    \033[91mEXISTEN CONFIGURACIONES PENDIENTES.\033[0m")
        print("="*100)
    
    print()
#=========================================================================================================

#=========================================================================================================
#VERIFICACIONES

#verificamos el paso 1
# Leemos primero el archivo 40_custom
# buscamos si tenemos superusers y password_pbkdf2
# leemos el fichero de configuración del GRUB
# buscamos si tenemos superusers y password_pbkdf2
# ambos ficheros tienen que tener la configuración
def verificar_paso1():
    print()
    print("="*100)
    print("[PASO 1]: Verificación de la protección del gestor de arranque GRUB.")
    print("="*100)

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



#verificamos paso 2
#comprobamos que el servicio está enmascarado

def verificar_paso2():
    print()
    print("="*100)
    print("[PASO 2]")
    print("="*100)

    resultado=subprocess.run(["systemctl", "is-enabled", "ctrl-alt-del.target"], capture_output=True, text=True)
    estado=resultado.stdout.strip()

    if estado=="masked":
        resultado_ok("ctrl-alt-del.target está enmascarado. La combinación de teclas está desactivada.")
    elif estado=="disabled":
        resultado_warn("ctrl-alt-del.target está deshabilitado pero no enmascarado.")
        resultado_warn("Se recomienda enmascarar usando el siguiente comando: sudo systemctl mask ctrl-alt-del.target")
    else:
        resultado_fail(f"ctrl-alt-del.target tiene estado: '{estado}'.", paso="Paso 2")
        resultado_fail("Ctrl+alt+delete puede reiniciar el sistema.", paso="Paso 2")

    #verificamos el estado para confirmar que está enmascarado

    resultado=subprocess.run(["systemctl", "status", "ctrl-alt-del.target"], capture_output=True, text=True)
    salida=resultado.stdout

    if "masked" in salida.lower():
        resultado_ok("Verificación cruzada: systemctl status confirma masked.")
    else:
        if estado=="masked":
            resultado_warn("Inconsistencia: is-enabled devuelve 'masked' pero status no lo confirma.")


#verificamos paso 3
#comprobamos que el fichero existe, las reglas están dentro del fichero y que el módulo de USB no está en memoria
def verificar_paso3():
    print()
    print("="*100)
    print("[PASO 3]: Almacenamiento USB deshabilitado")
    print("="*100)

    contenidoModprobe=leer_fichero(USB_MODPROBE_FILE, paso="Paso 3")
    if contenidoModprobe is None:
        resultado_fail(f"No se encontró {USB_MODPROBE_FILE}.", paso="Paso 3")
        resultado_fail("No hay regla de bloqueo para usb-storage.", paso="Paso 3")
    else:
        if "blacklist usb-storage" in contenidoModprobe:
            resultado_ok("Directiva 'blacklist usb-storage' presents.")
        else:
            resultado_fail("Falta la directiva'blacklist usb-storage'.", paso="Paso 3")

        if "install usb-storage /bin/false" in contenidoModprobe:
            resultado_ok("Directiva 'install usb-storage /bin/false' presente.")
        else:
            resultado_warn("Falta la directiva 'install usb-storage /bin/false'.")
            resultado_warn("El módulo podría cargarse manualmente con 'modprobe usb_storage'.")
    
    resultado=subprocess.run(["lsmod"], capture_output=True, text=True)
    if "usb_storage" in resultado.stdout:
        resultado_fail("El módulo usb_storage está cargado en memoria.", paso="Paso 3")
        resultado_fail("Ejecuta: sudo modprobe -r usb_storage", paso="Paso 3")
    else:
        resultado_ok("El módulo usb_storage NO está cargado en memoria.")

        
    resultado=subprocess.run(["modprobe", "--dry-run", "usb_storage"], capture_output=True, text=True)
    
    if resultado.returncode !=0:
        resultado_ok("modprobe confirma que usb_storage está bloqueado.")
    else:
        resultado_warn("modprobe podría cargar usb_storage (dry-run exitoso).")



#=========================================================================================================



  

def main():
    comprobar_root()
    configurar_logging()

    print()
    print("="*70)
    print("     VERIFICACIÓN: Módulo 1 - Seguridad en Acceso al Hardware - Ubuntu Server 24.04.4 LTS")
    print("="*70)
    print()
    print("         Comprobando configuraciones...")

    verificar_paso1()
    verificar_paso2()

    mostrar_resumen()

    if checksFail>0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__=="__main__":
    main()
