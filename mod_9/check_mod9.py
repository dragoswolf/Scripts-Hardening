#!/usr/bin/env python3


import os
import sys
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, comprobar_root, ejecutar_comando,
                   ejecutar_comando_check, volver_al_menu, leer_fichero,
                   resultado_fail, resultado_ok, resultado_warn, mostrar_resumen,
                   contadores)


LOG_FILE="/var/log/hardening/modulo9_check.log"

SSHD_CONFIG="/etc/ssh/sshd_config"


#Funciones auxiliares
def obtener_puerto_ssh():
    """
    Lee el puerto SSH configurado en sshd_config.

    Return:
        str: Número de puerto SSH configurado
    """

    contenido=leer_fichero(SSHD_CONFIG)

    if contenido is None:
        return "22"
    
    for linea in contenido.strip().splitlines():
        limpia=linea.strip()
        if limpia.startswith("Port ") and not limpia.startswith("#"):
            partes=limpia.split()
            if len(partes)>=2 and partes[1].isdigit():
                return partes[1]
            
    return "22"

def verificar_paso1():
    """
    Verifica que UFW está instalado, activo y con la política por defecto correcta (deny incoming, allow outgoing).
    """

    print()
    print("="*100)
    print("[PASO 1]: Verificar UFW instalado y activo.")
    print("="*100)
    print()

    paso="Paso 1"

    rc, _, _=ejecutar_comando_check(["dpkg", "-s", "ufw"])

    if rc==0:
        resultado_ok("Paquete ufw instalado")
    else:
        resultado_fail("Paquete ufw NO instalado", paso)
        return
    
    # 1. Verificar que UFW está activo
    rc, salida, _=ejecutar_comando_check(["ufw", "status", "verbose"])

    if rc!=0:
        resultado_fail("No se pudo obtener el estado de UFW", paso)
        return
    
    activo=False
    politicaInOk=False
    politicaOutOk=False

    for linea in salida.strip().splitlines():
        lineaLower=linea.strip().lower()

        if "status" in lineaLower and "active" in lineaLower and "inactive" not in lineaLower:
            activo=True
        
        if "default" in lineaLower and "incoming" in lineaLower:
            if "deny" in lineaLower or "reject" in lineaLower:
                politicaInOk=True
        
        if "default:" in lineaLower and "outgoing" in lineaLower:
            if "allow" in lineaLower:
                politicaOutOk=True

    if activo:
        resultado_ok("UFW está activo")
    else:
        resultado_fail("UFW no está activo", paso)

    if politicaInOk:
        resultado_ok("Política entrante: deny (denegar por defecto)")
    else:
        resultado_fail("Política entrante NO es deny", paso)

    if politicaOutOk:
        resultado_ok("Política saliente: allow (permitir por defecto)")
    else:
        resultado_warn("Política saliente no es allow (verificar manualmente)")

    # Verificar que UFW arranca con el sistema
    rc, _, _=ejecutar_comando_check(["systemctl", "is-enabled", "--quiet", "ufw"])

    if rc==0:
        resultado_ok("UFW habilitado en el arranque")
    else:
        resultado_fail("UFW no habilitado en el arranque", paso)


def verificar_paso2():
    """
    Verifica que UFW está instalado, activo y con la política por defecto correcta (deny incoming, allow outgoing).
    """

    print()
    print("="*100)
    print("[PASO 2]: Verificar que SSH está permitido.")
    print("="*100)
    print()

    paso="Paso 2"

    puertoSSH=obtener_puerto_ssh()

    rc, salida, _=ejecutar_comando_check(["ufw", "status"])

    if rc!=0:
        resultado_fail("No se pudo obtener reglas de UFW", paso)
        return
    
    sshPermitido=False
    
    for linea in salida.strip().splitlines():
        lineaLower=linea.strip().lower()

        if("allow" in lineaLower and (f"{puertoSSH}/tcp" in lineaLower or f"{puertoSSH}" in lineaLower)):
            sshPermitido=True
            break

    if sshPermitido:
        resultado_ok(f"SSH (puerto {puertoSSH}) permitido en el firewall")
    else:
        resultado_fail(f"SSH (puerto {puertoSSH}) NO tiene regla ALLOW en UFW. Riesgo de perder acceso remoto.", paso)


def verificar_paso3():
    """
    Verifica que el logging de UFW está activo.
    """

    print()
    print("="*100)
    print("[PASO 3]: Verificar logging de UFW")
    print("="*100)
    print()

    paso="Paso 3"

    rc, salida, _=ejecutar_comando_check(["ufw", "status", "verbose"])

    if rc!=0:
        resultado_fail("No se pudo obtener el estado de UFW", paso)
        return
    
    loggingActivo=False
    for linea in salida.strip().splitlines():
        lineaLower=linea.strip().lower()

        if "logging" in lineaLower and "on" in lineaLower:
            loggingActivo=True
            resultado_ok(f"Logging activo ({linea.strip()})")
            break

    if not loggingActivo:
        resultado_fail("Logging de UFW no está activo", paso)


def main():
    """
    Ejecuta todas las verificaciones del módulo de firewall y muestra el resumen final.
    """
    comprobar_root()
    configurar_logging(LOG_FILE)

    print()
    print("="*100)
    print("[AUDITORÍA MÓDULO 9]: Firewall")
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