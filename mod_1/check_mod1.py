#!/usr/bin/env python3

#=========================================================================================================
# check_mod1.py - Script de verificación para Módulo 1: Seguridad en Acceso al Hardware
#=========================================================================================================
# Este script verifica que las siguientes medidas de seguridad están correctamente configuradas
# en Ubuntu Server 24.04.4 LTS:
#       Paso 1: Protección del gestor de arranque GRUB con contraseña
#       Paso 2: Ctrl+Alt+Delete deshabilitado
#       Paso 3: Almacenamiento USB (usb-storage) deshabilitado
#
# Este script NO modifica nada en el sistema. Solo lee y comprueba.
#
# IMPORTANTE: El script ha de ejecutarse como root (sudo) para poder leer todos los ficheros
#             de configuración necesarios.
#
# Los errores se registran en /var/log/hardening/modulo1_check.log
#
# Auto: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================


import os           #Comprueba existencia de ficheros y permisos
import sys          #Para códigos de salida
import subprocess   #Ejecuta comandos de verificación
import getpass      #Para solicitar información sensible de forma segura
import logging      #Para logging de los comandos usados y el resultado de la ejecución
from datetime import datetime


#=========================================================================================================
# CONSTANTES GLOBALES - Ruta de los ficheros a verificar
#=========================================================================================================

#Fichero de configuración personalizada de GRUB (para el paso 1)
GRUB_CUSTOM_FILE="/etc/grub.d/40_custom"

#Fichero de configuración compilada de GRUB (generado por update-grub en el paso 1)
GRUB_CFG_FILE= "/boot/grub/grub.cfg"

#Fichero modprobe para el bloqueo de USB (paso 3)
USB_MODPROBE_FILE="/etc/modprobe.d/usb-storage.conf"

#Directorio y fichero de logs
LOG_DIR="/var/log/hardening"
LOG_FILE="/var/log/hardening/modulo1_fix.log"

#=========================================================================================================


#=========================================================================================================
# CONTADORES GLOBALES - Variables globales usadas para el resumen final
#=========================================================================================================

# Estas variables llevan la cuenta de verificaciones correctas y fallidas
totalChecks=0       #Número total de verificaciones realizadas
checksOk=0          #Número de verificaciones correctas
checksFail=0        #Número de verificaciones fallidas
checksWarn=0        #Número de advertencias

#=========================================================================================================

#=========================================================================================================
# FUNCIONES DE APOYO - Funciones utilizadas para realizar las funciones necesarias
#=========================================================================================================

# CONFIGURACIÓN DEL SISTEMA DE LOGS

def configurar_logging():
    """
    Configura el sistema de logging para registrar errores en un fichero.
    Crea el directorio /var/log/hardening/ si no existe.
    El fichero de log es /var/log/hardening/modulo1_check.log
    Cada entrada incluyte fecha, hora, nivel y mensaje.
    """
    #Crea el directorio de logs si no existe
    if not os.path.isdir(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)

    #Configura el logger con el formato "[YYYY-MM-DD HH:MM:SS] ERROR: <mensajeError>"
    logging.basicConfig(filename=LOG_FILE, 
                        level=logging.ERROR, 
                        format="[%(asctime)s] %(levelname)s: %(message)s", 
                        datefmt="%Y-%m-%d %H:%M:%S"
                        )
    
def registrar_errores(paso, mensaje):
    """
    Registra un error en el fichero de log y además lo muestra por pantalla

    Args:
        paso (str): Identificador del paso donde ocurrió el error (ej: "Paso 1").
        mensaje (str): Descripción del error.
    Return:
        None.
    """
    textoLog=f"[{paso}] {mensaje}"
    logging.error(textoLog)
    print(f"[ERROR]: {mensaje}")

# ASEGURAR USO DE SUDO

def comprobar_root():
    """
    Comprueba que el script se ejecuta como root.
    Necesario para leer ficheros protegidos (como /boot/grub/grub.cfg)
    """
    if os.geteuid()!=0:
        print("[ERROR]: Este script ha de ejecutarse como root.")
        print("         Ejecuta: sudo python3 fix_mod1.py")
        sys.exit(1)

# RECOGIDA DE RESULTADOS
def resultado_fail(mensaje, paso="General"):
    """
    Registra una verificación fallida y muestra el resultado en rojo.
    
    Args:
        mensaje (str): Descripción de lo que ha fallado
        paso (str): Identificador del paso para el log
    Return:
        None.
    """
    global totalChecks, checksFail
    totalChecks +=1
    checksFail +=1

    #imprimir en rojo el fallo y luego resetear el color. Esta logica se va a usar en todos los resultados
    print(f"    \033[91m[FALLO]:\033[0m {mensaje}")
    registrar_errores(paso, mensaje)

def resultado_warn(mensaje):
    """
    Registra una advertencia y muestra el resultado en amarillo.

    Args:
        mensaje (str): Descripción de la advertencia
    Return:
        None.
    """
    global totalChecks, checksWarn
    totalChecks+=1
    checksWarn+=1

    print(f"    \033[93m[AVISO]:\033[0m {mensaje}")

def resultado_ok(mensaje):
    """
    Registra una verificación exitosa y muestra el resultado en verde.

    Args:
        mensaje(str): Descripción de lo que se ha verificado correctamente.
    Return:
        None.
    """
    global totalChecks, checksOk
    totalChecks+=1
    checksOk+=1

    print(f"    \033[92m[CORRECTO]:\033[0m {mensaje}")

def leer_fichero(ruta, paso="General"):
    """
    Lee el contenido de un fichero y lo devuelve como string.
    Si el fichero no existe o no se puede leer, devuelve None.

    Args:
        ruta (str): Ruta ABSOLUTA del fichero
        paso (str): Identificador del paso para el log
    Return:
        str o None: Contenido del fichero, o None si hubo error
    """
    try:
        with open(ruta,"r") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Fichero {ruta} no encontrado.")
        return None
    except PermissionError:
        registrar_errores(paso, f"Sin permisos para leer {ruta}")
        return None
    
# RESUMEN FINAL
def mostrar_resumen():
    """
    Muestra un resumen de todas las verificaciones realizadas 
    con el conteo de éxitos, fallos y advertencias.
    """
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
# VERIFICACION PASO 1 - Protección del GRUB
#=========================================================================================================

def verificar_paso1():
    """
    Verifica que GRUB está protegido con contraseña. Comprueba:
    1. Que /etc/grub.d/40_custom contiene la directiva "set superusers"
    2. Que /etc/grub.d/40_custom contiene un hash "password_pbkdf2"
    3. Que /boot/grub/grub.cfg (generado) también incluye esas directivas
       Esto se utiliza para confirmar que se ejecutó "update-grub" tras la configuración.
    """
    print()
    print("="*100)
    print("[PASO 1]: Verificación de la protección del gestor de arranque GRUB.")
    print("="*100)

    # Verificamos si el fichero 40_custom existe
    contenidoCustom=leer_fichero(GRUB_CUSTOM_FILE, paso="Paso 1")
    if contenidoCustom is None:
        #Si el fichero no existe, GRUB no está protegido
        resultado_fail(
            f"No se encontró {GRUB_CUSTOM_FILE}. GRUB no tiene configuración de contraseña", 
            paso="Paso 1")
        return
    
    # Verificamos si la directiva "set superusers" está presente
    #Esta directiva define qué clase de usuarios pueden editar las entradas de GRUB
    if "set superusers" in contenidoCustom:
        #Extrae el nombre del superuser para mostrarlo
        for linea in contenidoCustom.splitlines():
            if "set superusers" in linea:
                resultado_ok(f"Superusuario GRUB configurado: {linea.strip()}")
                break
    else:
        resultado_fail(f"No se encontró la directiva 'set superusers' en {GRUB_CUSTOM_FILE}.", paso="Paso 1")

    #Verifica si existe el fichero "password_pbkdf2", en el cual se encuentra el hash de la contraseña
    if "password_pbkdf2" in contenidoCustom:
        resultado_ok(f"Hash PBKDF2 de contraseña GRUB presente en {GRUB_CUSTOM_FILE}.")
    else:
        resultado_fail(f"No se encontró hash 'password_pbkdf2' en {GRUB_CUSTOM_FILE}.", paso="Paso 1")

    
    #Verificamos que "grub.cfg" está compilado e incluye la protección
    #Después de ejecutar update-grub, la configuración de "40_custom" debe
    #aparecer también en /boot/grub/grub.cfg 
    contenidoCfg=leer_fichero(GRUB_CFG_FILE, paso="Paso 1")
    if contenidoCfg is not None:
        if "superusers" in contenidoCfg and "password_pbkdf2" in contenidoCfg:
            resultado_ok("Protección de GRUB presente en grub.cfg. 'update-grup' aplicado.")
        else:
            resultado_warn(f"{GRUB_CUSTOM_FILE} tiene configuración pero {GRUB_CFG_FILE} no la refleja.")
            resultado_warn("Ejecuta 'sudo update-grub' para aplicar los cambios.")
    else:
        resultado_warn(f"No se puede leer {GRUB_CFG_FILE} para la verificación cruzada")



#=========================================================================================================
# VERIFICACIÓN PASO 2 - CTRL+ALT+DEL deshabilitado
#=========================================================================================================

def verificar_paso2():
    """
    Verifica que Ctrl+alt+del está deshabilitado. Comprueba:
    1. Que ctrl-alt-del.target está enmascarado en systemd
    2. Que el enlace simbólico apunta a /dev/null
    """
    print()
    print("="*100)
    print("[PASO 2]")
    print("="*100)

    #systemctl is-enabled devuelve uno de los siguientes estados: enabled, disabled, masked, static, etc
    #Nos interesa sobre todo "masked" y "disabled".
    resultado=subprocess.run(["systemctl", "is-enabled", "ctrl-alt-del.target"], capture_output=True, text=True)
    estado=resultado.stdout.strip()

    if estado=="masked":
        #"masked" significa que el target apunta a /dev/null y no puede activarse
        resultado_ok("ctrl-alt-del.target está enmascarado. La combinación de teclas está desactivada.")
    elif estado=="disabled":
        #"disabled" significa que no se activa automáticamente, pero podría
        #activarse manualmente por alguna aplicación u otros usuarios.
        #No es tan seguro como "masked"
        resultado_warn("ctrl-alt-del.target está deshabilitado pero no enmascarado.")
        resultado_warn("Se recomienda enmascarar usando el siguiente comando: sudo systemctl mask ctrl-alt-del.target")
    else:
        #Cualquier otro estado significa que no está enmascarado y por lo tanto sigue activo.
        resultado_fail(f"ctrl-alt-del.target tiene estado: '{estado}'.", paso="Paso 2")
        resultado_fail("Ctrl+alt+delete puede reiniciar el sistema.", paso="Paso 2")

    #Verificación adicional más detallada de systemctl
    resultado=subprocess.run(["systemctl", "status", "ctrl-alt-del.target"], capture_output=True, text=True)
    salida=resultado.stdout

    #Busca la palabra "masked" en la salida de status
    if "masked" in salida.lower():
        resultado_ok("Verificación cruzada: systemctl status confirma masked.")
    else:
        #Si "is-enabled" dice "masked" pero "status" no lo confirma, hay incosistencia.
        if estado=="masked":
            resultado_warn("Inconsistencia: is-enabled devuelve 'masked' pero status no lo confirma.")


#=========================================================================================================
# VERIFICACIÓN PASO 3 - Deshabilitar USB
#=========================================================================================================

def verificar_paso3():
    """
    Verifica que el almacenamiento USB está deshabilitado. Comprueba:
    1. Que existe /etc/modprobe.d/usb-storage.conf con la regla blacklist
    2. Que la regla "instal... /bin/false" también está presente
    3. Que el módulo "usb_storage" NO está cargado en memoria.
    """
    print()
    print("="*100)
    print("[PASO 3]: Almacenamiento USB deshabilitado")
    print("="*100)

    #Verificamos si el fichero de configuración "modprobe" existe
    contenidoModprobe=leer_fichero(USB_MODPROBE_FILE, paso="Paso 3")
    if contenidoModprobe is None:
        resultado_fail(f"No se encontró {USB_MODPROBE_FILE}.", paso="Paso 3")
        resultado_fail("No hay regla de bloqueo para usb-storage.", paso="Paso 3")
    else:
        #La directiva "blacklist usb-storage" impide la carga automática del módulo
        if "blacklist usb-storage" in contenidoModprobe:
            resultado_ok("Directiva 'blacklist usb-storage' presents.")
        else:
            resultado_fail("Falta la directiva'blacklist usb-storage'.", paso="Paso 3")

        #La directiva "install usb-storage /bin/false" impide la carga manual del módulo
        if "install usb-storage /bin/false" in contenidoModprobe:
            resultado_ok("Directiva 'install usb-storage /bin/false' presente.")
        else:
            resultado_warn("Falta la directiva 'install usb-storage /bin/false'.")
            resultado_warn("El módulo podría cargarse manualmente con 'modprobe usb_storage'.")
    
    # "lsmod" lista todos los módulos del kernel actualmente cargados
    resultado=subprocess.run(["lsmod"], capture_output=True, text=True)
    if "usb_storage" in resultado.stdout:
        # Si el módulo está cargado, la regla no se ha aplicado correctamente
        resultado_fail("El módulo usb_storage está cargado en memoria.", paso="Paso 3")
        resultado_fail("Ejecuta: sudo modprobe -r usb_storage", paso="Paso 3")
    else:
        #El módulo no está cargado, todo está correcto
        resultado_ok("El módulo usb_storage NO está cargado en memoria.")

    #Verificamos que las directivas en modprobe están activas
    resultado=subprocess.run(["modprobe", "--showconfig"], capture_output=True, text=True)
    configModprobe=resultado.stdout
    
    if "install usb-storage /bin/false" in configModprobe or "install usb_storage /bin/false" in configModprobe:
        resultado_ok("modprobe confirma directiva 'install usb-storage /bin/false' activa.")
    else:
        resultado_warn("No se detecta la directiva 'install usb-storage /bin/false' en modprobe.")
        print("El módulo podría cargarse manualmente con 'modprobe usb_storage'.")



#=========================================================================================================



  
def main():
    """
    Función principal. Ejecuta todas las verificaciones en orden y muestra el resumen final.
    """

    #Verifica permisos de root
    comprobar_root()

    #Inicializa el sistema de logging
    configurar_logging()

    #Cabecera del script
    print()
    print("="*70)
    print("     VERIFICACIÓN: Módulo 1 - Seguridad en Acceso al Hardware - Ubuntu Server 24.04.4 LTS")
    print("="*70)
    print()
    print("         Comprobando configuraciones...")

    #Funciones para ejecutar las verificaciones en orden
    verificar_paso1()   #GRUB protegido
    verificar_paso2()   #Ctrl+Alt+Del deshabilitado
    verificar_paso3()   #USB deshabilitado

    #Mostrar resumen final con contadores
    mostrar_resumen()

    #Devolver código de salida según resultado
    #0 = todo bien, 1= hay fallos
    if checksFail>0:
        sys.exit(1)
    else:
        sys.exit(0)

#=========================================================================================================
# PUNTO DE ENTRADA
#=========================================================================================================
if __name__=="__main__":
    main()
