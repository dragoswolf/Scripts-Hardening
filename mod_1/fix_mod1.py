#!/usr/bin/env python3

import os
import sys
import subprocess
import getpass
import logging
from datetime import datetime


#Ficheros de conf y directorios importantes
GRUB_CUSTOM_FILE="/etc/grub.d/40_custom"
USB_MODPROBE_FILE="/etc/modprobe.d/usb-storage.conf"
LOG_DIR="/var/log/hardening"
LOG_FILE="/var/log/hardening/modulo1_fix.log"


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

#función para pedirle input al usuario
#hace doble check para garantizar un input correcto
def pedir_input_doble(mensaje, ocultar=False):
    while True:
        if ocultar:
            entrada1=getpass.getpass(f"{mensaje}: ")
        else:
            entrada1=input(f"{mensaje}: ")
        if not entrada1.strip():
            print("[ERROR]: El valor no puede ser estar vacío.\n")
            continue
        
        if ocultar:
            entrada2=getpass.getpass(f"{mensaje} (confirmar): ")
        else:
            entrada2=input(f"{mensaje} (confirmar): ")
        
        if entrada1==entrada2:
            return entrada1
        else:
            print("[ERROR]: Las entradas no coinciden. Inténtalo de nuevo.\n")


#función para ejecutar comandos, el corazón de la aplicación
def ejecutar_comando(comando, descripcion, paso="General", capturarSalida=False):
    try:
        resultado=subprocess.run(comando, capture_output=True, text=True, check=True)
        if capturarSalida:
            return resultado.stdout
        return None
    except subprocess.CalledProcessError as e:
        mensajeError=(f"Fallo al {descripcion}: " 
                      f"Comando: {' '.join(comando)} | " 
                      f"Error: {e.stderr.strip()}")
        registrar_errores(paso, mensajeError)
        return None
    except FileNotFoundError:
        mensajeError=(f"Comando no encontrado: {comando[0]}. " 
                      f"Asegúrate de que está instalado.")
        registrar_errores(paso, mensajeError)
        return None

#función para volver al menú
def volver_al_menu():
    print()
    input("Pulsa ENTER para volver al menú principal...")



def paso1_proteger_grub():
    print("[PASO 1]: Proteger el gestor de arranque GRUB con contraseña.")

    #1.Pedimos credenciales
    print()
    nombreGrub=pedir_input_doble("Nombre de superusuario para GRUB (ej: admin): ")
    print()
    contrasenaGrub=pedir_input_doble("Contraseña para GRUB: ", ocultar=True)

    #2. Generar el hash con la password
    comando=[f"echo {contrasenaGrub} | grub-mkpasswd-pbkdf2"]
    proceso=subprocess.run(comando, capture_output=True, text=True)

    #3. Guardar el hash generado
    hashLinea=proceso.stdout

    #4.Formatear el archivo de configuración
    contenidoGrub=f"""
        set superusers="{nombreGrub}"
        password_pbkdf2 {nombreGrub} {hashLinea}
    """
    #5.Sobreescribir el archivo
    f=open(GRUB_CUSTOM_FILE, "w")
    f.write(contenidoGrub)
    f.close()

    #6. Actualizar GRUB
    ejecutar_comando("update-grub", "actualizar GRUB", "Paso 1")

    print()
    print("[CORRECTO]: PASO 1 COMPLETADO: GRUB protegido con contraseña.")
    print(f"                              Usuario GRUB: {nombreGrub}")
    print("                               Al editar entradas de GRUB (tecla 'e'), se pedirá autenticación")
    

