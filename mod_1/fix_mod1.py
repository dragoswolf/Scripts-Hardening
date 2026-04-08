#!/usr/bin/env python3

#=========================================================================================================
# fix_mod1.py - Script de fortificación para Módulo 1: Seguridad en Acceso al Hardware
#=========================================================================================================
# Este script implementa las siguientes medidas de seguridad en Ubuntu Server 24.04.4 LTS
#       Paso 1: Proteger el gestor de arranque GRUB con contraseña
#       Paso 2: Deshabilitar Ctrl+Alt+Delete 
#       Paso 3: Deshabilitar almacenamiento USB (usb-storage)
#       Paso 4: Rehabilitar almacenamiento USB (usb-storage)
#
#
# IMPORTANTE: El script ha de ejecutarse como root (sudo) para poder realizar los cambios
#
# Los errores se registran en /var/log/hardening/modulo1_fix.log
#
# Auto: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================


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


# menú
def mostrar_menu():
    print()
    print("="*100)
    print("     IMPLEMENTACIÓN: Módulo 1 - Seguridad en Acceso al Hardware -  Ubuntu Server 24.04.4 LTS")
    print("="*100)
    print()
    print("     Opciones:")
    print("         1. Proteger el gestor de arranque GRUB con contraseña.")
    print("         2. Enmascarar Ctrl+Alt+Delete.")
    print("         3. Deshabilitar USB.")
    print("         4. Rehabilitar USB.")
    print("         q. Salir.")
#=========================================================================================================




#FUNCIONES DE MODIFICACIÓN
#=========================================================================================================

def paso1_proteger_grub():
    print("\n" + "="*70)
    print("[PASO 1]: Proteger el gestor de arranque GRUB con contraseña.")
    print("\n" + "="*70)
    print()
    print("Esta medida impide que un atacante con acceso a la consola edite")
    print("las entradas de GRUB para obtener una shell root sin contraseña.")
    print()

    #abrir archivo grub para verificación
    try:
        with open(GRUB_CUSTOM_FILE, "r") as f:
            contenidoActual=f.read()
        
        if "set superusers" in contenidoActual:
            print("[INFO]: GRUB ya tiene una configuración de superusuario")
            respuesta=input("Desea sobreescribirla? (s/n): ").strip().lower()
            if respuesta!="s":
                print("[INFO]: PASO 1 OMITIDO. La configuración actual se mantiene.")
                return
    except FileNotFoundError:
        print("[AVISO]: No se encontró /etc/grub.d/40_custom. Se creará automáticamente.")
    
    # pedimos credenciales
    print()
    nombreGrub=pedir_input_doble("Nombre de superusuario para GRUB (ej: admin): ")
    print()
    contrasenaGrub=pedir_input_doble("Contraseña para GRUB: ", ocultar=True)

    #genrando hash
    print()
    print("\n[INFO]: Generando hash PBKDF2 de la contraseña...")
    try:
        proceso=subprocess.run(
            ["grub-mkpasswd-pbkdf2"], 
            input=f"{contrasenaGrub}\n{contrasenaGrub}\n", 
            capture_output=True, 
            text=True, 
            check=True)
        
    except subprocess.CalledProcessError as e:
        registrar_errores("Paso 1", f"No se pudo generar el hash PBKDF2: {e.stderr}")
        return
    except FileNotFoundError:
        registrar_errores("Paso 1", "grub-mkpasswd-pbkdf2 no encontrado. Está GRUB2 instalado?")
        return
    
    hashLinea=None
    for linea in proceso.stdout.splitlines():
        if "grub.pbkdf2" in linea:
            hashLinea=linea.split("is ")[-1].strip()
            break

    if not hashLinea:
        registrar_errores("Paso 1", f"No se pudo extraer el hash. Salida: {proceso.stdout}")
        return
    
    #escribiendo en GRUB_CUSTOM_FILE. #!/bin/sh necesario para poder ejecutar el comando
    #necesitamos exec tail -n n3 $0 para incrustar los datos en el archivo
    # n3= desde la linea 3 hasta el final
    #$0 = variable para ruta y archivo
    contenidoGrub=f"""#!/bin/sh
exec tail -n +3 $0
set superusers="{nombreGrub}"
password_pbkdf2 {nombreGrub} {hashLinea}
"""
    
    try:
        #también crea el archivo si no existe
        with open(GRUB_CUSTOM_FILE, "w") as f:
            f.write(contenidoGrub)
        #0o755 son permisos en octal (0o)
        os.chmod(GRUB_CUSTOM_FILE, 0o755)
        print(f"[CORRECTO]: Configuración escrita en {GRUB_CUSTOM_FILE}")
    except PermissionError:
        registrar_errores("Paso 1", f"Sin permisos para escribir en {GRUB_CUSTOM_FILE}")
        return
    
    #ejecutando update-grub para aplicar cambios
    ejecutar_comando(["update-grub"], "actualizar GRUB", "Paso 1")

    print()
    print("[CORRECTO]: PASO 1 COMPLETADO: GRUB protegido con contraseña.")
    print(f"                              Usuario GRUB: {nombreGrub}")
    print("                               Al editar entradas de GRUB (tecla 'e'), se pedirá autenticación.")




def paso2_deshabilitar_ctrl_alt_del():

    print()
    print("="*100)
    print("[PASO 2]: Deshabilitar Ctrl+Alt+Delete")
    print("="*100)
    print("Esta medida impide que se use ctrl+alt+del para reiniciar el servidor o interrumpir servicios.")
    print()

    resultado=subprocess.run(["systemctl", "is-enabled", "ctrl-alt-del.target"], capture_output=True, text=True)
    estadoActual=resultado.stdout.strip()

    if estadoActual=="masked":
        print("[INFO]: Ctrl+alt+delete ya está deshabilitado.")
        return
    
    print("[INFO]: Deshabilitando ctrl-alt-del.target...")
    ejecutar_comando(["systemctl", "mask", "ctrl-alt-del.target"], "enmascarar ctrl-alt-del.target", "Paso 2")

    print("[INFO]: Recargando configuración de systemd...")
    ejecutar_comando(["systemctl", "daemon-reload"], "recargar systemd", "Paso 2")

    print()
    print("[CORRECTO]: PASO 2 COMPLETADO: Ctrl+alt+del deshabilitado.")
    print()


def paso3_deshabilitar_usb():
    print()
    print("="*100)
    print("[PASO 3]: Deshabilitar almacenamiento USB (usb-storage).")
    print("="*100)
    print()
    print("Esta medida impide que se conecten dispositivos de almacenamiento")
    print("USB al servidor, previniendo la exfiltración de datos y ataques")
    print("BadUSB. Los teclados y ratones USB NO se ven afectados.")
    print()


    if os.path.isfile(USB_MODPROBE_FILE):
        try:
            with open(USB_MODPROBE_FILE, "r") as f:
                contenido=f.read()
            if "blacklist usb-storage" in contenido:
                print(f"[INFO]: La regla ya existe en {USB_MODPROBE_FILE}.")
                print("[CORRECTO] PASO 3: No se requieren cambios en la configuración.")

                #comprobamos que no esta en memoria y si está lo descargamos de memoria
                resultado=subprocess.run(["lsmod"], capture_output=True, text=True)

                if "usb_storage" in resultado.stdout:
                    print("[INFO]: El módulo usb_storage aún está cargado en memoria.")
                    print("[INFO]: Descargando módulo...")
                    ejecutar_comando(["modprobe", "-r", "usb-storage"], "descargar módulo usb_storage", "Paso 3")
                    print("[CORRECTO]: Módulo descargado de memoria.")
                return
        except PermissionError:
            registrar_errores("Paso 3", f"Sin permisos para leer {USB_MODPROBE_FILE}")

    print(f"[INFO]: Creando regla de bloqueo en {USB_MODPROBE_FILE}...")
    contenidoModprobe="""
blacklist usb-storage
install usb-storage /bin/false
"""

    try:
        with open(USB_MODPROBE_FILE, "w") as f:
            f.write(contenidoModprobe)
        print(f"[CORRECTO]: Regla de bloqueo creada en {USB_MODPROBE_FILE}")
    except PermissionError:
        registrar_errores("Paso 3", f"Sin permisos para escribir en {USB_MODPROBE_FILE}")
        return
    
    print("[INFO]: Actualizando initframfs (puede tardar unos segundos)...")
    ejecutar_comando(["update-initramfs", "-u"],"actualizar initramfs", "Paso 3")
    print("[CORRECTO]: initramfs actualizado.")

    resultado=subprocess.run(["lsmod"], capture_output=True, text=True)
    if "usb_storage" in resultado.stdout:
        print("[INFO]: El módulo usb_storage está cargado. Descargando... Si diese error, los cambios se aplicarán tras un reinicio del sistema.")
        ejecutar_comando(["modprobe","-r","usb_storage"],"descargar módulo usb_storage", "Paso 3")
        print("[CORRECTO]: Módulo usb_storage descargado de memoria")
    else:
        print("[INFO]: El módulo usb_storage no esta cargado.")


    print()
    print("[CORRECTO]: PASO 3 COMPLETADO: Almacenamiento USB deshabilitado.")
    print("            Los pendrives y discos USB ya no serán reconocidos.")
    print("            Teclados y ratones USB siguen funcionando con normalidad.")


#deshacemos los cambios hechos en el paso 3 para poder volver a cargar USBs
def paso4_reactivar_usb():
    print()
    print("="*100)
    print("[PASO 4]: Reactivar almacenamiento USB (reversión)")
    print("="*100)
    print()
    print("Esta opción revierte el bloqueo de USB y permite volver a")
    print("conectar dispositivos de almacenamiento USB al servidor.")
    print()
    print("[AVISO]: Solo usa esta opción si necesitas conectar un")
    print("         dispositivo USB temporalmente.")
    print("         Se recomienda volver a deshabilitar USB después.")
    print()

    confirmación= input("¿Estás seguro de que deseas reactivar USB? (s/n)").strip().lower()

    if confirmacion!="s":
        print("[INFO]: Operación cancelada. USB sigue deshabilitado.")
        return
    
    if os.path.isfile(USB_MODPROBE_FILE):
        try:
            os.remove(USB_MODPROBE_FILE)
            print(f"[CORRECTO]: Fichero de bloqueo eliminado: {USB_MODPROBE_FILE}")
        except PermissionError:
            registrar_errores("Paso 4", f"Sin permisos para eliminar {USB_MODPROBE_FILE}")
            return
    else:
        print(f"[INFO]: {USB_MODPROBE_FILE} no existe (USB puede que ya esté activado)")

    #actualizamos initial ram file system para el reinicio
    print("[INFO]: Actualizando initramfs...")
    ejecutar_comando(["update-initramfs", "-u"], "actualizar initramfs", "Paso 4")
    print("[CORRECTO]: initramfs actualizado.")
    
    print("[INFO]: Cargando módulo usb_storage en memoria...")
    ejecutar_comando(["modprobe","usb_storage"], "cargar módulo usb_storage", "Paso 4")

    #verificar que el módulo USB está en memoria. Si diese error es posible
    # que se necesite un reinicio del sistema

    resultado=subprocess.run(["lsmod"], capture_output=True, text=True)

    if "usb_storage" in resultado.stdout:
        print("[CORRECTO]: Módulo 'usb_storage' cargado correctamente.")
    else:
        registrar_errores("Paso 4", "El módulo 'usb_storage' no se cargó tras modprobe")

    print()
    print("[CORRECTO]: PASO 4 COMPLETADO: Almacenamiento USB reactivado.")
    print("                               Los pendrives y discos USB serán")
    print("                               reconocidos de nuevo.")
    print()
    print("[AVISO]: RECUERDA DESHABILITAR USB CUANDO TERMINES.")


#=========================================================================================================







#EJECUCIÓN
def main():
    comprobar_root()
    configurar_logging()

    while True:
        mostrar_menu()
        opcion=input("Selecciona una opción: ").strip().lower()

        match opcion:
            case "1":
                paso1_proteger_grub()
                volver_al_menu()
            case "2":
                paso2_deshabilitar_ctrl_alt_del()
                volver_al_menu()
            case "3":
                paso3_deshabilitar_usb()
                volver_al_menu()
            case "4":
                paso4_reactivar_usb()
                volver_al_menu()
            case "q":
                print("\n[INFO]: Saliendo del script.")
                sys.exit(0)
            case _:
                print("[ERROR]: Opción no válida. Inténtelo de nuevo.")

if __name__=="__main__":
    main()



