#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, registrar_errores, comprobar_root,
                   ejecutar_comando, ejecutar_comando_check, volver_al_menu)


LOG_FILE="/var/log/hardening/modulo8_fix.log"

PAQUETES_BASE=["apparmor", "apparmor-utils"]
PAQUETES_PERFILES=["apparmor-profiles", "apparmor-profiles-extra"]


# Funciones auxiliares

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


def paso1_instalar_apparmor():
    print()
    print("="*100)
    print("[PASO 1]: Verificar que AppArmor está instalado y activo")
    print("="*100)
    print()

    paso="Paso 1"

    paquetesFaltantes=[]

    for paquete in PAQUETES_BASE:
        rc, _, _=ejecutar_comando_check(["dpkg", "-s", paquete])

        if rc!=0:
            paquetesFaltantes.append(paquete)

    if paquetesFaltantes:
        print(f"[INFO]: Instalando paquetes: {', '.join(paquetesFaltantes)}")
        ejecutar_comando(["apt-get", "install", "-y"] + paquetesFaltantes, "instalar paquetes base de AppArmor", paso, mostrarSalida=True)
        print()
    else:
        print(f"[CORRECTO]: Paquetes base instalados: {', '.join(PAQUETES_BASE)}")

    rc, _, _=ejecutar_comando_check(["systemctl", "is-active", "--quiet", "apparmor"])

    if rc!=0:
        print("[INFO]: Activando servicio AppArmor...")
        ejecutar_comando(["systemctl", "enable", "--now", "apparmor"], "activar servicio AppArmor", paso)
    else:
        print("[CORRECTO]: Servicio 'apparmor' activo.")
    
    rc, salida, _=ejecutar_comando_check(["aa-enabled"])

    if rc==0 and "yes" in salida.lower():
        print("[CORRECTO]: AppArmor habilitado en el kernel.")
    else:
        print("[AVISO]: AppArmor no está habilitado en el kernel.")
        print("         Puede ser necesario añadir 'apparmor=1' y 'security=apparmor'"
              "         a los parámetros del kernel en GRUB y reiniciar el sistema.")
        registrar_errores(paso, "AppArmor no habilitado en el kernel")

    print()

    estado=obtener_estado_apparmor()
    if estado:
        print(f"[INFO]: Perfiles cargados:  {estado['loaded']}")
        print(f"        En modo enforce:    {estado['enforce']}")
        print(f"        En modo complain:   {estado['complain']}")


def paso2_enforce_perfiles():
    print()
    print("="*100)
    print("[PASO 2]: Poner todos los perfiles en modo enforce")
    print("="*100)
    print()

    paso="Paso 2"

    perfilesComplain=obtener_perfiles_complain()

    if not perfilesComplain:
        print("[CORRECTO]: Todos los perfiles ya están en modo enforce.")
        return
    
    print(f"[INFO]: {len(perfilesComplain)} perfil(es) en modo complain.")
    
    for perfil in perfilesComplain:
        print(f"    - {perfil}")
    print()

    errores=0
    for perfil in perfilesComplain:
        rc, _, stderr= ejecutar_comando_check(["aa-enforce", perfil])

        if rc==0:
            print(f"[CORRECTO]: {perfil} -> enforce")
        else:
            print(f"[ERROR]: No se pudo cambiar {perfil}:"
                  f"{stderr.strip()}")
            registrar_errores(paso, f"No se pudo cambiar {perfil}"
                              f"a enforce: {stderr.strip()}")
            errores+=1

    print()
    if errores==0:
        print(f"[CORRECTO]: {len(perfilesComplain)} perfil(es) cambiados a modo enforce.")
    else:
        print(f"[AVISO]: {errores} perfil(es) no se pudieron cambiar.")


def paso3_perfiles_adicionales():
    print()
    print("="*100)
    print("[PASO 3]: Instalar perfiles adicionales de AppArmor")
    print("="*100)
    print()

    paso="Paso 3"

    paquetesFaltantes=[]
    for paquete in PAQUETES_PERFILES:
        rc, _, _=ejecutar_comando_check(["dpkg", "-s", paquete])
        if rc!=0:
            paquetesFaltantes.append(paquete)

    if paquetesFaltantes:
        print(f"[INFO]: Instalando: {', '.join(paquetesFaltantes)}")
        ejecutar_comando(["apt-get", "install", "-y"] + paquetesFaltantes, "instalando perfiles adicionales de AppArmor", paso, mostrarSalida=True)
        print()
    else:
        print(f"[CORRECTO]: Paquetes de perfiles ya instalados: "
              f"{', '.join(PAQUETES_PERFILES)}")
    
    print()
    print("[INFO]: Poniendo perfiles nuevos en modo enforce...")
    print()

    perfilesComplain=obtener_perfiles_complain()
    
    if not perfilesComplain:
        print("[CORRECTO]: Todos los perfiles están en modo enforce.")
    else:
        errores=0
        for perfil in perfilesComplain:
            rc, _, stderr=ejecutar_comando_check(["aa-enforce", perfil])

            if rc != 0:
                print(f"[CORRECTO]: {perfil} -> enforce")
            else:
                print(f"[ERROR]: No se pudo cambiar {perfil}:"
                      f"{stderr.strip()}")
                registrar_errores(paso, f"No se pudo cambiar {perfil} a enforce: {stderr.strip()}")
                errores+=1
            
        print()
        cambios=len(perfilesComplain) - errores

        if cambios >0:
            print(f"[CORRECTO]: {cambios} perfil(es) adicional(es) en modo enforce.")

    print()
    estado=obtener_estado_apparmor()

    if estado:
        print(f"[INFO]: Perfiles cargados:  {estado['loaded']}")
        print(f"        En modo enforce:    {estado['enforce']}")
        print(f"        En modo complain:   {estado['complain']}")


def mostar_menu():
    print()
    print("="*100)
    print("Hardening: AppArmor (Mandatory Access Control))")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Verificar que AppArmor está instalado y activo.")
    print("     2. Poner todos los perfiles en modo enforce.")
    print("     3. Instalar perfiles adicionales de AppArmor")
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
                paso2_enforce_perfiles()
                volver_al_menu()
            case "3":
                paso3_perfiles_adicionales()
                volver_al_menu()
            case "q":
                print("\n[INFO]: Saliendo del script.")
                sys.exit(0)
            case _:
                print("[ERROR]: Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()
    