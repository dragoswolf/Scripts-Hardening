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


import os                           #Para operaciones del sistema de ficheros
import sys                          #Para salir del script con códigos de error
import subprocess                   #Para ejecutar comandos del sistema

#Importar utils.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__),".."))
from utils import(
    configurar_logging,
    registrar_errores,
    comprobar_root,
    ejecutar_comando,
    volver_al_menu,
    pedir_input_doble
)

#=========================================================================================================
# CONSTANTES - Rutas de ficheros necesarios a modificar por los scripts
#=========================================================================================================

#Fichero donde GRUB permite añadir configuración personalizada (paso 1)
GRUB_CUSTOM_FILE="/etc/grub.d/40_custom"

#Fichero de configuración de modprobe para bloquear módulos del kernel (paso 3)
USB_MODPROBE_FILE="/etc/modprobe.d/usb-storage.conf"

#Fichero de logs
LOG_FILE="/var/log/hardening/modulo1_fix.log"
#=========================================================================================================

#=========================================================================================================
# FUNCIÓN DE MENÚ
#=========================================================================================================

def mostrar_menu():
    """
    Muestra el menú principal del script, permitiendo al usuario elegir qué paso ejecutar.
    """
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


#=========================================================================================================
# PASO 1: Proteger el gestor de arranque GRUB
#=========================================================================================================
def paso1_proteger_grub():
    """
    Protege GRUB2 con contraseña para evitar que un atacante edite las entradas de arranque
    (tecla "e") y añada parámetros como init=/bin/bash que darían acceso root sin autenticación.

    Proceso:
    1. Pedir al usuario un nombre de superusuario para GRUB
    2. Pedir una contraseña (doble verificación)
    3. Generar el hash PBKDF2 de la contraseña con grub-mkpasswd-pbkdf2
    4. Añadir la configuración al fichero /etc/grub.d/40_custom
    5. Ejecutar update-grub para aplicar los cambios
    """
    print("\n" + "="*70)
    print("[PASO 1]: Proteger el gestor de arranque GRUB con contraseña.")
    print("\n" + "="*70)
    print()
    print("Esta medida impide que un atacante con acceso a la consola edite")
    print("las entradas de GRUB para obtener una shell root sin contraseña.")
    print()

    #Comprobamos si GRUB ya está protegido
    try:
        #Leemos el fichero 40_custom para ver si ya tiene configuración de superusuario
        with open(GRUB_CUSTOM_FILE, "r") as f:
            contenidoActual=f.read()
        #Si ya existe la directiva "set superusers", GRUB ya está protegida
        if "set superusers" in contenidoActual:
            print("[INFO]: GRUB ya tiene una configuración de superusuario")
            respuesta=input("Desea sobreescribirla? (s/n): ").strip().lower()
            if respuesta!="s":
                print("[INFO]: PASO 1 OMITIDO. La configuración actual se mantiene.")
                return
    except FileNotFoundError:
        #Si el fichero no existe, lo crearemos más adelante
        print("[AVISO]: No se encontró /etc/grub.d/40_custom. Se creará automáticamente.")
    
    #Se pide el nombre de superusuario para GRUB. Este superuser se usará para autenticarse
    print()
    nombreGrub=pedir_input_doble("Nombre de superusuario para GRUB (ej: admin): ")

    #Se pide la contraseña para el superuser. Se oculta la entrada
    print()
    contrasenaGrub=pedir_input_doble("Contraseña para GRUB: ", ocultar=True)

    #Generamos el hash PBKDF2 de la contraseña
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

    #Extraer el hash de la salida del comando
    #La salida tiene el formato:
    #"PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.XXX...XXX"
    hashLinea=None
    for linea in proceso.stdout.splitlines():
        #Buscamos la línea que contiene el hash generado
        if "grub.pbkdf2" in linea:
            #El hash está después del "is " en la línea
            hashLinea=linea.split("is ")[-1].strip()
            break

    #Verificar que se extrajo correctamente
    if not hashLinea:
        registrar_errores("Paso 1", f"No se pudo extraer el hash. Salida: {proceso.stdout}")
        return
    
    #Escribimos la configuración en /etc/gurb.d/40_custom.
    # "#!/bin/sh" necesario al inicio para poder ejecutar el comando
    #Necesitamos exec tail -n n3 $0 para incrustar los datos en el archivo
    # n3= desde la linea 3 hasta el final
    #$0 = variable para ruta y archivo
    contenidoGrub=f"""#!/bin/sh
exec tail -n +3 $0
set superusers="{nombreGrub}"
password_pbkdf2 {nombreGrub} {hashLinea}
"""
    
    try:
        #Crea el archivo si no existe
        with open(GRUB_CUSTOM_FILE, "w") as f:
            f.write(contenidoGrub)
        #0o755 son permisos en octal (0o)
        os.chmod(GRUB_CUSTOM_FILE, 0o755)
        print(f"[CORRECTO]: Configuración escrita en {GRUB_CUSTOM_FILE}")
    except PermissionError:
        registrar_errores("Paso 1", f"Sin permisos para escribir en {GRUB_CUSTOM_FILE}")
        return
    
    #Ejecutando update-grub para aplicar cambios.
    #update-grub regenera /boot/grub/grub.cfg incluyendo nuestro 40_custom
    ejecutar_comando(["update-grub"], "actualizar GRUB", "Paso 1")

    print()
    print("[CORRECTO]: PASO 1 COMPLETADO: GRUB protegido con contraseña.")
    print(f"                              Usuario GRUB: {nombreGrub}")
    print("                               Al editar entradas de GRUB (tecla 'e'), se pedirá autenticación.")



#=========================================================================================================
# PASO 2: Deshabilitar Ctrl+Alt+Del
#=========================================================================================================
def paso2_deshabilitar_ctrl_alt_del():
    """
    Deshabilita la combinación de teclas Ctrl+Alt+Del que, por defecto, puede usarse para reiniciar
    el sistema. Un atacante con acceso a la consola podría usar esta combinación para provocar una 
    denegación de servicio.

    Proceso:
    1. Enmascarar el target ctrl-alt-del.target de systemd
    2. Recargar la configuración de systemd
    """
    print()
    print("="*100)
    print("[PASO 2]: Deshabilitar Ctrl+Alt+Delete")
    print("="*100)
    print("Esta medida impide que se use ctrl+alt+del para reiniciar el servidor o interrumpir servicios.")
    print()

    #Comprobamos el estado actual y verificamos si el target ya está enmascarado
    resultado=subprocess.run(["systemctl", "is-enabled", "ctrl-alt-del.target"], capture_output=True, text=True)
    estadoActual=resultado.stdout.strip()

    if estadoActual=="masked":
        #Si ya está enmascarado, no hay nada que hacer
        print("[INFO]: Ctrl+alt+delete ya está deshabilitado.")
        return
    
    #Si no está enmascarado el target, lo enmascaramos
    #systemctl mask crea un enlace simbólico a /dev/null, haciendo que
    #el target sea imposible de activar (ni manual ni automáticamente)
    print("[INFO]: Deshabilitando ctrl-alt-del.target...")
    ejecutar_comando(["systemctl", "mask", "ctrl-alt-del.target"], "enmascarar ctrl-alt-del.target", "Paso 2")

    #Recargamos systemd mediante daemon-reload.
    print("[INFO]: Recargando configuración de systemd...")
    ejecutar_comando(["systemctl", "daemon-reload"], "recargar systemd", "Paso 2")

    print()
    print("[CORRECTO]: PASO 2 COMPLETADO: Ctrl+alt+del deshabilitado.")
    print()

#=========================================================================================================
# PASO 3: Deshabilitar almacenamiento USB
#=========================================================================================================
def paso3_deshabilitar_usb():
    """
    Deshabilita el módulo del kernel usb-storage para impedir que el sistema reconozca dispositivos
    de almacenamiento USB. Esto previene la exfiltración de datos y la introducción de malware mediante
    pendrives.

    Nota: Solo afecta a dispositivos de almacenamiento (pendrives, discos USB).
    Los teclados y ratones USB siguen funcionando normalmente.

    Proceso:
    1. Crear regla de blacklist en /etc/modprobe.d/usb-storage.conf
    2. Actualizar initramfs para que el cambio se aplique desde el arranque
    3. Descargar el módulo si está actualmente cargado
    """
    print()
    print("="*100)
    print("[PASO 3]: Deshabilitar almacenamiento USB (usb-storage).")
    print("="*100)
    print()
    print("Esta medida impide que se conecten dispositivos de almacenamiento")
    print("USB al servidor, previniendo la exfiltración de datos y ataques")
    print("BadUSB. Los teclados y ratones USB NO se ven afectados.")
    print()

    #Comprobar si ya existe la regla
    if os.path.isfile(USB_MODPROBE_FILE):
        try:
            with open(USB_MODPROBE_FILE, "r") as f:
                contenido=f.read()
            if "blacklist usb-storage" in contenido:
                print(f"[INFO]: La regla ya existe en {USB_MODPROBE_FILE}.")
                print("[CORRECTO] PASO 3: No se requieren cambios en la configuración.")
                #A pesar de todo, verificamos si el módulo está cargado.
                resultado=subprocess.run(["lsmod"], capture_output=True, text=True)

                if "usb_storage" in resultado.stdout:
                    #Si está cargado, lo descargamos de memoria
                    print("[INFO]: El módulo usb_storage aún está cargado en memoria.")
                    print("[INFO]: Descargando módulo...")
                    ejecutar_comando(["modprobe", "-r", "usb-storage"], "descargar módulo usb_storage", "Paso 3")
                    print("[CORRECTO]: Módulo descargado de memoria.")
                return
        except PermissionError:
            registrar_errores("Paso 3", f"Sin permisos para leer {USB_MODPROBE_FILE}")

    #Creamos el fichero de configuración de modprobe
    #La directiva "blacklist" evita la carga automática del módulo
    #La directiva "install ... /bin/false" impide también la carga manual
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
    
    #Actualizamos initramfs
    #"initramfs" es la imagen de arranque inicial. update-initramfs regenera esta
    #imagen incluyendo nuestra configuración de modprobe, de forma que el bloqueo de
    #USB se aplique desde el primer momento del arranque
    print("[INFO]: Actualizando initframfs (puede tardar unos segundos)...")
    ejecutar_comando(["update-initramfs", "-u"],"actualizar initramfs", "Paso 3")
    print("[CORRECTO]: initramfs actualizado.")

    #Descargamos el módulo si está cargado
    #"lsmod" lista los módulos del kernel actualmente cargados.
    resultado=subprocess.run(["lsmod"], capture_output=True, text=True)
    if "usb_storage" in resultado.stdout:
        #Si el módulo está cargado, lo descargamos inmediatamente
        #modprobe -r descarga (remove) un módulo del kernel
        print("[INFO]: El módulo usb_storage está cargado. Descargando... Si diese error, los cambios se aplicarán tras un reinicio del sistema.")
        ejecutar_comando(["modprobe","-r","usb_storage"],"descargar módulo usb_storage", "Paso 3")
        print("[CORRECTO]: Módulo usb_storage descargado de memoria")
    else:
        print("[INFO]: El módulo usb_storage no esta cargado.")


    print()
    print("[CORRECTO]: PASO 3 COMPLETADO: Almacenamiento USB deshabilitado.")
    print("            Los pendrives y discos USB ya no serán reconocidos.")
    print("            Teclados y ratones USB siguen funcionando con normalidad.")


#=========================================================================================================
# PASO 4: Reactivar almacenamiento USB
#=========================================================================================================
def paso4_reactivar_usb():
    """
    Revierte el bloqueo de almacenamiento USB realizado en el paso 3.
    Esto permite volver a conectar pendrives y discos USB al servidor
    en caso de que sea necesario (mantenimiento, copias de seguridad, etc)

    Proceso:
    1. Eliminar el fichero /etc/modprobe.d/usb-storage.confg
    2. Actualizar initramfs para reflejar el cambio
    3. Cargar el módulo usb_storage en memoria
    """
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

    #Reactivar USB reduce la seguridad, así que pedimos confirmación
    confirmacion= input("¿Estás seguro de que deseas reactivar USB? (s/n)").strip().lower()

    if confirmacion!="s":
        print("[INFO]: Operación cancelada. USB sigue deshabilitado.")
        return
    
    #Eliminar el fichero de bloqueo de modprobe
    if os.path.isfile(USB_MODPROBE_FILE):
        try:
            os.remove(USB_MODPROBE_FILE)
            print(f"[CORRECTO]: Fichero de bloqueo eliminado: {USB_MODPROBE_FILE}")
        except PermissionError:
            registrar_errores("Paso 4", f"Sin permisos para eliminar {USB_MODPROBE_FILE}")
            return
    else:
        print(f"[INFO]: {USB_MODPROBE_FILE} no existe (USB puede que ya esté activado)")

    #Actualizamos initramfs, regenerando la imagen de arranque sin la regla de bloqueo de USB
    print("[INFO]: Actualizando initramfs...")
    ejecutar_comando(["update-initramfs", "-u"], "actualizar initramfs", "Paso 4")
    print("[CORRECTO]: initramfs actualizado.")
    
    #Cargamos el módulo usb_storage. "modprobe" carga un módulo del kernel en memoria inmediatamente
    print("[INFO]: Cargando módulo usb_storage en memoria...")
    ejecutar_comando(["modprobe","usb_storage"], "cargar módulo usb_storage", "Paso 4")

    #Verificar que el módulo USB está en memoria. Si diese error es posible
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


def main():
    """
    Función principal del script. Comprueba permisos de root, configura el sistema de logs,
    muestra el menú y ejecuta los pasos seleccionados por el usuario.
    """

    #Verificar que se ejecuta como root
    comprobar_root()

    #Configurar el sistema de logs
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


#=========================================================================================================
# PUNTO DE ENTRADA - Se ejecuta solo si el fichero se llama directamente.
#=========================================================================================================
if __name__=="__main__":
    main()





