#!/usr/bin/env python3
#=========================================================================================================
# fix_mod8.py - Script de fortificación para el módulo 8 - AppArmor (Mandatory Access Control)
#=========================================================================================================
# Este script implementa las siguientes medidas de seguridad:
#
#   Paso 1: Verificar que AppArmor está instalado y activo
#   Paso 2: Poner todos los perfiles en modo enforce
#   Paso 3: Instalar perfiles adicionales de AppArmor
#
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo8_fix.log
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================


import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, 
                   registrar_errores, 
                   comprobar_root,
                   ejecutar_comando, 
                   ejecutar_comando_check, 
                   volver_al_menu,
                   print_aviso,
                   print_correcto,
                   print_error,
                   print_info)


#=========================================================================================================
# CONSTANTES
#=========================================================================================================

LOG_FILE="/var/log/hardening/modulo8_fix.log"

PAQUETES_BASE=["apparmor", "apparmor-utils"]
PAQUETES_PERFILES=["apparmor-profiles", "apparmor-profiles-extra"]
#=========================================================================================================


#=========================================================================================================
# FUNCIONES AUXILIARES
#=========================================================================================================
def obtener_estado_apparmor():
    """
    Obtiene un resumen dele stado de AppArmor usando aa-status.

    Return:
        dict: Diccionario con claves 'loaded', 'enforce, 'complain',
              'unconfined'. Valores son enteros.
        None: Si no se pudo obtener el estado
    """

    rc, salida, _=ejecutar_comando_check(["aa-status"])

    if rc!=0:
        return None
    
    estado={
        "loaded": 0,
        "enforce": 0,
        "complain": 0,
        "unconfined": 0,
    }

    for linea in salida.splitlines():
        linea=linea.strip().lower()
        
        if "profiles are loaded" in linea:
            try:
                estado["loaded"] = int(linea.split()[0])
            except (ValueError, IndexError):
                pass
        elif "profiles are in enforce mode" in linea:
            try:
                estado["enforce"]=int(linea.split()[0])
            except (ValueError, IndexError):
                pass
        elif "profiles are in complain mode" in linea:
            try:
                estado["complain"]=int(linea.split()[0])
            except (ValueError, IndexError):
                pass
        elif "processes are unconfined" in linea:
            try:
                estado["unconfined"]=int(linea.split()[0])
            except (ValueError, IndexError):
                pass
    
    return estado



def obtener_perfiles_complain():
    """
    Obtiene la lista de perfiles de AppArmor que están en modo complain.

    Return:
        lista: Lista de nombres de perfiles en modo complain
    """

    rc, salida, _=ejecutar_comando_check(["aa-status"])

    if rc!=0:
        return []
    
    perfiles = []
    enSeccionComplain=False
    for linea in salida.splitlines():
        limpia=linea.strip()

        if "profiles are in complain mode" in limpia.lower():
            enSeccionComplain=True
            continue
        if enSeccionComplain:
            if "profiles are" in limpia.lower() or "processes are" in limpia.lower():
                break
            if limpia:
                nombre=limpia.replace(" (complain)", "").strip()
                if nombre:
                    perfiles.append(nombre)

    return perfiles
#=========================================================================================================

def paso1_instalar_apparmor():
    """
    Verifica que AppArmor y sus utilidades están instalados, el servicio está activo
    y el módulo del kernel está cargado.
    """
    print()
    print("="*100)
    print("[PASO 1]: Verificar que AppArmor está instalado y activo")
    print("="*100)
    print_info("Verifica que AppArmor y sus utilidades están instalados,\n" \
    "       está activo y el módulo del kernel está cargado.")
    print()

    paso="Paso 1"

    # 1a. Verificar/instalar paquetes base
    paquetesFaltantes=[]
    for paquete in PAQUETES_BASE:
        rc, _, _=ejecutar_comando_check(["dpkg", "-s", paquete])

        if rc!=0:
            paquetesFaltantes.append(paquete)

    if paquetesFaltantes:
        print_info(f"Instalando paquetes: {', '.join(paquetesFaltantes)}")
        ejecutar_comando(["apt-get", "install", "-y"] + paquetesFaltantes, "instalar paquetes base de AppArmor", paso, mostrarSalida=True)
        print()
    else:
        print_correcto(f"Paquetes base instalados: {', '.join(PAQUETES_BASE)}")

    # 1b. Verificar que el servicio está activo.
    rc, _, _=ejecutar_comando_check(["systemctl", "is-active", "--quiet", "apparmor"])
    if rc!=0:
        print_info("Activando servicio AppArmor...")
        ejecutar_comando(["systemctl", "enable", "--now", "apparmor"], "activar servicio AppArmor", paso)
    else:
        print_correcto("Servicio 'apparmor' activo.")
    
    # 1c. Verificar que el módulo del kernel está cargado
    rc, salida, _=ejecutar_comando_check(["aa-enabled"])
    if rc==0 and "yes" in salida.lower():
        print_correcto("AppArmor habilitado en el kernel.")
    else:
        print_aviso("AppArmor no está habilitado en el kernel.")
        print_info("Puede ser necesario añadir 'apparmor=1' y 'security=apparmor'" \
        " a los parámetros del kernel en GRUB y reiniciar el sistema.")
        registrar_errores(paso, "AppArmor no habilitado en el kernel")

    print()

    # 1d. Mostrar resumen
    estado=obtener_estado_apparmor()
    if estado:
        print_info(f"Perfiles cargados:  {estado['loaded']}")
        print_info(f"En modo enforce:    {estado['enforce']}")
        print_info(f"En modo complain:   {estado['complain']}")


def paso2_perfiles_adicionales():
    """
    Instala los paquetes de perfiles adicionales de AppArmor y los pone en 
    modo enforce.
    """
    print()
    print("="*100)
    print("[PASO 2]: Instalar perfiles adicionales de AppArmor")
    print("="*100)
    print_info("Instala los paquetes de perfiles adicionales de AppArmor y los pone\n" \
    "       en modo enforce.")
    print()

    paso="Paso 2"

    # 2a. Verificar/instalar paquetes de perfiles
    paquetesFaltantes=[]
    for paquete in PAQUETES_PERFILES:
        rc, _, _=ejecutar_comando_check(["dpkg", "-s", paquete])
        if rc!=0:
            paquetesFaltantes.append(paquete)

    if paquetesFaltantes:
        print_info(f"Instalando: {', '.join(paquetesFaltantes)}")
        ejecutar_comando(["apt-get", "install", "-y"] + paquetesFaltantes, "instalando perfiles adicionales de AppArmor", paso, mostrarSalida=True)
        print()
    else:
        print_correcto(f"Paquetes de perfiles ya instalados: "
              f"{', '.join(PAQUETES_PERFILES)}")
    
    # 2b. Poner los nuevos perfiles en modo enforce
    print()
    print_info("Poniendo perfiles nuevos en modo enforce...")
    print()

    perfilesComplain=obtener_perfiles_complain()
    
    if not perfilesComplain:
        print_correcto("Todos los perfiles están en modo enforce.")
    else:
        errores=0
        for perfil in perfilesComplain:
            rc, _, stderr=ejecutar_comando_check(["aa-enforce", perfil])

            if rc != 0:
                print_correcto(f"{perfil} -> enforce")
            else:
                print_error(f"No se pudo cambiar {perfil}:"
                      f"{stderr.strip()}")
                registrar_errores(paso, f"No se pudo cambiar {perfil} a enforce: {stderr.strip()}")
                errores+=1
            
        print()
        cambios=len(perfilesComplain) - errores

        if cambios >0:
            print_correcto(f"{cambios} perfil(es) adicional(es) en modo enforce.")

    print()
    estado=obtener_estado_apparmor()

    # 2c. Mostrar estado final
    if estado:
        print_info(f"Perfiles cargados:  {estado['loaded']}")
        print_info(f"En modo enforce:    {estado['enforce']}")
        print_info(f"En modo complain:   {estado['complain']}")



def paso3_enforce_perfiles():
    """
    Cambia todos los perfiles que estén en modo complain (solo registro) 
    a modo enforce (bloqueo activo de accesos no permitidos)
    """
    print()
    print("="*100)
    print("[PASO 3]: Poner todos los perfiles en modo enforce")
    print("="*100)
    print_info("Cambia todos los perfiles que estén en modo complain (solo registro)\n" \
    "       a modo enforce (bloqueo activo de accesos no permitidos)")
    print()

    paso="Paso 2"

    # 3a. Obtener perfiles en complain
    perfilesComplain=obtener_perfiles_complain()

    if not perfilesComplain:
        print_correcto("Todos los perfiles ya están en modo enforce.")
        return
    
    print_info(f"{len(perfilesComplain)} perfil(es) en modo complain.")
    
    for perfil in perfilesComplain:
        print(f"    - {perfil}")
    print()

    # 3b. Cambiar cada perfil a enforce
    errores=0
    rc, salida, stderr=ejecutar_comando_check(["bash","-c","aa-enforce /etc/apparmor.d/*"])

    if rc==0:
        print_correcto("Todos los perfiles cambiados a enforce")
    else:
        print_error(f"{stderr.strip()}")
        errores+=1

    # 3c. Mostrar resumen
    print()
    if errores==0:
        print_correcto(f"{len(perfilesComplain)} perfil(es) cambiados a modo enforce.")
    else:
        print_aviso(f"{errores} perfil(es) no se pudieron cambiar.")




def mostar_menu():
    print()
    print("="*100)
    print("Hardening: AppArmor (Mandatory Access Control).")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Verificar que AppArmor está instalado y activo.")
    print("     2. Instalar perfiles adicionales de AppArmor")
    print("     3. Poner todos los perfiles en modo enforce.")
    print()
    print("     q. Salir")
    print()


def main():
    configurar_logging(LOG_FILE)
    comprobar_root()

    while True:
        mostar_menu()
        opcion=input("Selecciona una opción: ").strip().lower()

        match opcion:
            case "1":
                paso1_instalar_apparmor()
                volver_al_menu()
            case "2":
                paso2_perfiles_adicionales()
                volver_al_menu()
            case "3":
                paso3_enforce_perfiles()
                volver_al_menu()
            case "q":
                print_info("Saliendo del script.")
                sys.exit(0)
            case _:
                print_error("Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()
    