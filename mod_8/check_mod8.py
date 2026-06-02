#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, resultado_fail, resultado_ok, mostrar_resumen, 
                   contadores, ejecutar_comando_check, comprobar_root)


LOG_FILE="/var/log/hardening/modulo8_check.log"

PAQUETES_BASE=["apparmor", "apparmor-utils"]
PAQUETES_PERFILES=["apparmor-profiles", "apparmor-profiles-extra"]

def verificar_paso1():
    print()
    print("="*100)
    print("[PASO 1]: Verificar que AppArmor está instalado y activo")
    print("="*100)
    print()

    paso="Paso 1"

    for paquete in PAQUETES_BASE:
        rc,_,_= ejecutar_comando_check(["dpkg", "-s", paquete])

        if rc==0:
            resultado_ok(f"Paquete {paquete} instalado.")
        else:
            resultado_fail(f"Paquete {paquete} NO instalado", paso)
    
    rc,_,_=ejecutar_comando_check(["systemctl", "is-active", "--quiet", "apparmor"])

    if rc==0:
        resultado_ok("Servicio apparmor activo")
    else:
        resultado_fail("Servicio apparmor NO activo", paso)

    rc, salida, _= ejecutar_comando_check(["aa-enabled"])

    if rc==0 and "yes" in salida.lower():
        resultado_ok("AppArmor Habilitado en el kernel")
    else:
        resultado_fail("AppArmor NO habilitado en el kernel", paso)


def verificar_paso2():
    print()
    print("="*100)
    print("[PASO 2]: Verificar perfiles en modo enforce")
    print("="*100)
    print()

    paso="Paso 2"

    rc, salida, _=ejecutar_comando_check(["aa-status"])

    if rc!=0:
        resultado_fail("No se pudo ejecutar aa-status", paso)
        return
    
    numEnforce=0
    numComplain=0
    numLoaded=0

    for linea in salida.strip().splitlines():
        linea=linea.strip().lower()
        
        if "profiles are loaded" in linea:
            try:
                numLoaded = int(linea.split())
            except (ValueError, IndexError):
                pass
        elif "profiles are in enforce mode" in linea:
            try:
                numEnforce=int(linea.split())
            except (ValueError, IndexError):
                pass
        elif "profiles are in complain mode" in linea:
            try:
                numComplain=int(linea.split())
            except (ValueError, IndexError):
                pass
    
    if numLoaded==0:
        resultado_fail("No hay perfiles de AppArmor cargados", paso)
        return
    
    resultado_ok(f"{numLoaded} perfil(es) cargados en total.")

    if numComplain==0:
        resultado_ok(f"Todos los perfiles ({numEnforce}) en modo enforce.")
    else:
        resultado_fail(f"{numComplain} perfil(es) en modo complain (deberían estar en enforce).", paso)

        rc2, salida2,_=ejecutar_comando_check(["aa-status", "--complaining"])

        if rc==0:
            for linea in salida2.strip().splitlines():
                linea=linea.strip()
                if linea and not linea.isdigit():
                    print(f"    - {linea}")


def verificar_paso3():
    print()
    print("="*100)
    print("[PASO 3]: Verificar perfiles adicionales de AppArmor")
    print("="*100)
    print()

    paso="Paso 3"

    for paquete in PAQUETES_PERFILES:
        rc, _, _=ejecutar_comando_check(["dpkg", "-s", paquete])

        if rc==0:
            resultado_ok(f"Paquete {paquete} instalado.")
        else:
            resultado_fail(f"Paquete {paquete} NO instalado", paso)


def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    print()
    print("="*100)
    print("[AUDITORÍA MÓDULO 8]: AppArmor (Mandatory Access Control).")
    print("="*100)
    print()

    print()
    print("     Comprobando configuraciones de los pasos 1 al 3...")
    print()

    verificar_paso1()
    verificar_paso2()
    verificar_paso3()


    mostrar_resumen("fix_mod8.py")

    if contadores["checksFail"]>0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__=="__main__":
    main()