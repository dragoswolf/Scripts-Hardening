#!/usr/bin/env python3

#=======================================================================================================
#Funciones comunes para los scripts de hardening
#=======================================================================================================
#Este módulo centraliza las funciones auxiliares que se repiten en los scripts de verificación
#y correción de cada módulo.
#
# USO:
#   Desde cualquier script de módulo
#   import sys, os
#   sys.path.insert(0, os.path.join(os.path.dirname(__file__),".."))
#   from utils import (configurar_logging, registrar_error, comprobar_root, ejecutar_comando, volver_al_menu)
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=======================================================================================================

import os
import sys
import subprocess
import logging
import getpass

#=======================================================================================================
# GLOBALES
#=======================================================================================================
LOG_DIR="/var/log/hardening"

#=======================================================================================================
# Configuración del sistema de logs
#=======================================================================================================

def configurar_logging(logFile):
    """
    Configura el sistema de logging para registrar errores en un fichero.
    Crea el directorio /var/log/hardening/ si no existe
    Cada entrada incluye fecha, hora, nivel y mensaje.

    Args:
        logFile (str): Ruta completa al fichero de log
                        (ej: "/var/log/hardening/modulo1_fix.log)
    
    Return:
        None
    """

    #Crea el directorio de logs si no existe
    if not os.path.isdir(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)

    #Configurar el logger con formato [YYYY-MM-DD HH:MM:SS] ERROR: <mensajeError>

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
        #os.geteuid() devuelve el UID efectivo del proceso. 0=root
        print("[ERROR]: Este script ha de ejecutarse como root.")
        print("         Ejecuta: sudo python3 fix_mod1.py")
        sys.exit(1)


#=======================================================================================================
# FUNCIONES COMUNES PARA SCRIPTS DE CORRECIÓN
#
# Estas funciones son comunmente usadas por los scripts de correción
#=======================================================================================================

def ejecutar_comando(comando, descripcion, paso="General", capturarSalida=False, mostrarSalida=False):
    """
    Ejecuta un comando del sistema y gestiona posibles errores.
    Los errores se registran tanto en pantalla como en el fichero de log.

    Args:
        comando (list): Lista con el comando y sus argumentos.
        descripcion (str): Texto descriptivo de lo que hace el comando
        paso (str): Identificador del paso
        capturarSalida (bool): Si es True, captura y devuelve stdout.
        mostrarSalida (bool): Si es True, la salida del comando se muestra
                              en la terminal en tiempo real (sin capturar).
                              Útil para comandos largos donde es necesario
                              ver el progreso para saber que todo sigue 
                              en marcha.

    Return:
        str o None: La salida del comando si capturarSalida=True, None en otro caso
    """

    try:
        if mostrarSalida:
            #Modo interactivo: stdout y stderr van directos a la terminal, para ver el progreso en tiempo real
            resultado=subprocess.run(comando, check=True)
            return None
        else:
            #subprocess.run() ejecuta el comando como un proceso hijo
            resultado=subprocess.run(
                comando,                #Comando a ejecutar
                capture_output=True,    #Capturar stdout y stderr
                text=True,              #Devolver strings en vez de bytes
                check=True              #Lanzar excepción si el código de retorno !=0
            )
            if capturarSalida:
                return resultado.stdout #Devolver la salida estándar
            return None
        
    except subprocess.CalledProcessError as e:
        #Si el comando falla (código de retorno != 0), registrar el error
        # En el modo mostrarSalida, stderr ya se mostró en pantalla
        errorTexto=e.stderr.strip() if e.stderr else "ver salida anterior"
        mensajeError=(f"Fallo al {descripcion}: " 
                        f"Comando: {' '.join(comando)} | " 
                        f"Error: {errorTexto}")
        registrar_errores(paso, mensajeError)
        return None
    except FileNotFoundError:
        #Si el ejecutable no existe en el sistema.
        mensajeError=(f"Comando no encontrado: {comando[0]}. " 
                        f"Asegúrate de que está instalado.")
        registrar_errores(paso, mensajeError)
        return None


def volver_al_menu():
    """
    Espera a que el usuario pulse Enter para volver al menú principal.
    """
    print()
    input("Pulsa ENTER para volver al menú principal...")

def escribir_fichero(ruta, contenido, permisos=None, paso="General"):
    """
    Escribe contenido en un fichero. Si el fichero existe, lo sobreescribe.

    Args:
        ruta (str): Ruta absoluta al fichero
        contenido (str): Contenido a escribir
        permisos (int o None): Permisos en octal (ej:0o640). None = no cambiar.
        paso (str): Identificador del paso (para el log).

    Return:
        bool: True si se escribió correctamente, False en caso de error.
    """

    try:
        with open(ruta, "w") as f:
            f.write(contenido)
        if permisos is not None:
            os.chmod(ruta, permisos)
        return True
    except PermissionError:
        registrar_errores(paso, f"[ERROR]: Sin permisos para escribir en {ruta}")
        return False
    except Exception as e:
        registrar_errores(paso, f"[ERROR]: No se puede escribir en {ruta}: {e}")
        return False
    
def leer_fichero(ruta, paso="General"):
    """
    Lee el contenido de un fichero y lo devuelve como string.
    Si el fichero no existe o no se puede leer, devuelve None.

    Args:
        ruta (str): Ruta absoluta al fichero.
        paso (str): Identificador del paso para el log (ej: "Paso 1")
    
    Return:
        str o None: Contenido del fichero, o None si hubo error
    """

    try:
        with open(ruta, "r") as f:
            return f.read()
    except FileNotFoundError:
        #El fichero no existe en el sistema
        return None
    except PermissionError:
        #No tenemos permisos para leer el fichero
        registrar_errores   (paso, f"[ERROR]: Sin permisos para leer {ruta}")
        return None
    

def pedir_input_doble(mensaje, ocultar=False):
    """
    Solicita un dato al usuario DOS veces y compara ambas entradas.
    Si coinciden, devuelve el valor, si no coinciden vuelve a pedir las dos entradas.
    Estos previene errores tipográficos en contraseñas, nombres de usuarios o rutas de dispositivos.

    Args:
        mensaje (str): El texto que se muestra al usuario.
        ocultar (bool): Si es True, no se muestra lo que el usuario escribe (ej: contraseñas)
                        Usa getpass en lugar de input

    Return:
        str: El valor introducido por el usuario (verificado por doble entrada).
    """
    while True:
        #Primera entrada: Se pide el dato por primera vez
        if ocultar:
            #getpass() no muestra los caracteres en pantalla
            entrada1=getpass.getpass(f"{mensaje}: ")
        else:
            #input() muestra los caracteres normalmente
            entrada1=input(f"{mensaje}: ")
        #Validar que no esté vacío
        if not entrada1.strip():
            print("[ERROR]: El valor no puede ser estar vacío.\n")
            continue
        
        #Segunda entrada: se pide lo mismo para confirmar
        if ocultar:
            entrada2=getpass.getpass(f"{mensaje} (confirmar): ")
        else:
            entrada2=input(f"{mensaje} (confirmar): ")
        
        #Comparación: si ambas entradas coinciden, se acepta el valor
        if entrada1==entrada2:
            return entrada1
        else:
            #Si no coinciden, se informa al usuario y se repite el proceso
            print("[ERROR]: Las entradas no coinciden. Inténtalo de nuevo.\n")
    

#=======================================================================================================
# FUNCIONES COMUNES PARA SCRIPTS DE VERIFICACIÓN
#=======================================================================================================
# Los contadores se gestionan como un diccionario mutable para poder modificarlos
# desde los scripts que importen este módulo sin usar variables globales

contadores={
    "totalChecks": 0,
    "checksOk": 0,
    "checksFail": 0,
    "checksWarn":0
}

def resultado_ok(mensaje):
    """
    Registra una verificación exitosa y muestra el resultado en verde.

    Args:
        mensaje(str): Descripción de lo que se ha verificado correctamente.
    Return:
        None.
    """
    contadores["totalChecks"] +=1
    contadores["checksOk"] += 1

    print(f"    \033[92m[CORRECTO]:\033[0m {mensaje}")

def resultado_fail(mensaje, paso="General"):
    """
    Registra una verificación fallida y muestra el resultado en rojo.
    
    Args:
        mensaje (str): Descripción de lo que ha fallado
        paso (str): Identificador del paso para el log
    Return:
        None.
    """
    contadores["totalChecks"]+=1
    contadores["checksFail"]+=1

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
    contadores["totalChecks"]+=1
    contadores["checksWarn"]+=1

    print(f"    \033[93m[AVISO]:\033[0m {mensaje}")

def mostrar_resumen(nombreFix="fix_<modulo>.py"):
    """
    Muestra un resumen de todas las verificaciones realizadas 
    con el conteo de éxitos, fallos y advertencias.

    Args:
        nombreFix (str): Nombre del script de correción correspondiente,
                        para mostrarlo en el mensaje de fallos.
    """
    print()
    print("="*100)
    print("RESUMEN DE VERIFICACIÓN")
    print("="*100)
    print()

    print(f"    Total de verificaciones: {contadores["totalChecks"]}")
    print(f"    \033[92mCorrectamente configurado: {contadores["checksOk"]}\033[0m")
    print(f"    \033[91mConfiguraciones fallidas: {contadores["checksFail"]}\033[0m")    
    print(f"    \033[93mAdvertencias: {contadores["checksWarn"]}\033[0m")
    print()

    if contadores["checksFail"]==0 and contadores["checksWarn"]==0:
        print("="*100)
        print("    \033[92m[CORRECTO]: TODAS LAS CONFIGURACIONES SON CORRECTAS\033[0m")
        print("="*100)
    elif contadores["checksFail"]==0:
        print("="*100)
        print("    \033[93m[AVISO]: EXISTEN ADVERTENCIAS. REVISARLAS.\033[0m")
        print("="*100)
    else:
        print("="*100)
        print("    \033[91m[AVISO]: EXISTEN CONFIGURACIONES PENDIENTES.\033[0m")
        print("="*100)
    
    print()

def ejecutar_comando_check(comando, mostrarSalida=False):
    """
    Ejecuta un comando del sistema y devuelve su salida estándar.
    Versión para scripts de verificación que devuelve una tupla.

    Args:
        comando (list): Lista con el comando y sus argumentos.
        mostrarSalida (bool): Si es True, la salida se muestra en la
                              terminal en tiempo real.
    Return:
        tuple: (codigoRetorno, salidaStdout, salidaStderr)
    """

    try:
        if mostrarSalida:
            resultado=subprocess.run(comando)
            return (resultado.returncode, "", "")
        else:
            resultado=subprocess.run(comando, capture_output=True, text=True)
            return (resultado.returncode, resultado.stdout, resultado.stderr)

    except FileNotFoundError:
        return (127, "", f"[ERROR]: Comando no encontrado: {comando[0]}")