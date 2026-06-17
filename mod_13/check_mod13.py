#!/usr/bin/env python3
#=========================================================================================================
# check_mod13.py - Script de verificación para el módulo 13 - Fail2Ban
#=========================================================================================================
# Este script implementa las siguientes medidas de seguridad:
#
#   Paso 1: Verificar que Fail2Ban está instalado
#   Paso 2: Verificar que Fail2Ban está activo y habilitado
#   Paso 3: Verificar que existe jail.local con configuración personalizada
#   Paso 4: Verificar que el jail SSH está habilitado y funcionando
#   Paso 5: Verificar que la whitelist está configurada
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo13_check.log
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================

import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging,
                   comprobar_root,
                   ejecutar_comando_check,
                   leer_fichero,
                   resultado_fail,
                   resultado_ok,
                   resultado_warn,
                   mostrar_resumen,
                   contadores)

#=========================================================================================================
# CONSTANTES
#=========================================================================================================
LOG_FILE="/var/log/hardening/modulo13_check.log"
JAIL_LOCAL="/etc/fail2ban/jail.local"
#=========================================================================================================
# VERIFICACIONES
#=========================================================================================================

def verificar_paso1():
    """
    Verifica que el paquete Fail2Ban está instalado en el sistema
    """
    print()
    print("="*100)
    print("[PASO 1]: Verificar existencia de Fail2Ban.")
    print("="*100)
    print()
    paso="Paso 1"

    rc, _, _=ejecutar_comando_check(["dpkg", "-s", "fail2ban"])
    if rc==0:
        # obtener la versión
        rc2, salida,_=ejecutar_comando_check(["fail2ban-clietn", "--version"])

        if rc2==0:
            resultado_ok(f"Fail2Ban instalado ({salida.strip()}).")
        else:
            resultado_ok("Fail2Ban instalado.")
    else:
        resultado_fail("Fail2Ban no está instalado", paso)


def verificar_paso2():
    """
    Verifica que el servicio fail2ban está activo y habilitado en el arranque del sistema
    """
    print()
    print("="*100)
    print("[PASO 2]: Verificar que el servicio fail2ban está activo y habilitado.")
    print("="*100)
    print()
    paso="Paso 2"

    # 2a. Verificar si está activo
    rc, salida, _=ejecutar_comando_check(["systemctl", "is-active", "fail2ban"])

    if rc==0 and "active" in salida.strip():
        resultado_ok("Servicio fail2ban: activo")
    else:
        resultado_fail("Servicio fail2ban: inactivo", paso)
    

    # 2b. Verificar si está habilitado en el arranque
    rc, salida, _=ejecutar_comando_check(["systemctl", "is-enabled", "fail2ban"])
    if rc==0 and "enabled" in salida.strip():
        resultado_ok("Servicio fail2ban: habilitado en el arranque")
    else:
        resultado_fail("Servicio fail2ban: no habilitado en el arranque", paso)


def verificar_paso3():
    """
    Verifica que existe el fichero jail.local con los parámetros de configuración esperados.
    """
    print()
    print("="*100)
    print("[PASO 3]: Verificar que el servicio fail2ban está activo y habilitado.")
    print("="*100)
    print()
    paso="Paso 3"

    contenido=leer_fichero(JAIL_LOCAL)

    # 3a. Verificar jail.local
    if contenido is None:
        resultado_fail(f"{JAIL_LOCAL} no existe", paso)
        return
    resultado_ok(f"{JAIL_LOCAL} existe. Verificando parámetros...")

    # 3b. Verificar parámetros clave
    parametros={
        "bantime": False,
        "findtime": False,
        "maxretry": False,
        "banaction": False,
    }

    for linea in contenido.splitlines():
        limpia = linea.strip()
        if limpia.startswith("#"):
            continue
        for param in parametros:
            if limpia.startswith(param):
                parametros[param] = True
        
    for param, encontrado in parametros.items():
        if encontrado:
            resultado_ok(f"Parámetro '{param}' configurado.")
        else:
            resultado_fail(f"Parámetro '{param}' no encontrado en jail.local.", paso)
    
    # 3c. Verificar que banaction usa UFW
    if "banaction" in contenido:
        for linea in contenido.splitlines():
            limpia = linea.strip()
            if limpia.startswith("banaction") and "ufw" in limpia:
                resultado_ok("Backend de bloqueo: UFW")
                break
        else:
            resultado_warn("banaction no usa UFW como backend.")


def verificar_paso4():
    """
    Verifica que existe el fichero jail.local con los parámetros de configuración esperados.
    """
    print()
    print("="*100)
    print("[PASO 4]: Verificar que el Jail SSH está activo.")
    print("="*100)
    print()
    paso="Paso 4"

    rc, salida,_=ejecutar_comando_check(["fail2ban-client", "status", "sshd"])
    if rc==0:
        resultado_ok("Jail SSH (sshd) está activo")

        #Extraer información del jail
        for linea in salida.splitlines():
            limpia=linea.strip()
            if "Currently banned" in limpia:
                resultado_ok(f" {limpia}")
            elif "Total banned" in limpia:
                resultado_ok(f" {limpia}")
            elif "File list" in limpia:
                resultado_ok(f" {limpia}")
    else:
        resultado_fail("Jail SSH (sshd) inactivo o no configurado.", paso)


def verificar_paso5():
    """
    Verifica que la whitelist está configurada en jail.local y contiene al menos localhost.
    """
    print()
    print("="*100)
    print("[PASO 5]: Verificar que la whitelist está configurada.")
    print("="*100)
    print()
    paso="Paso 5"

    # Comprobar existencia de jail.lock
    contenido = leer_fichero(JAIL_LOCAL)
    if contenido is None:
        resultado_fail("jail.locl no existe. Whitelist no se puede verificar.")
        return
    
    # 5a. Verificar que existen IPs
    ignoreip=None
    for linea in contenido.splitlines():
        limpia=linea.strip()
        if limpia.startswith("ignoreip"):
            ignoreip=limpia.split("=", 1)[1].strip()
            break

    if ignoreip is None:
        resultado_fail("ignoreip no configurado en jail.local.", paso)
        return
    resultado_ok(f"ignoreip configurado: {ignoreip}")

    # 5b. Verificar que incluye localhost
    if "127.0.0.1" in ignoreip or "127.0.0.1" in ignoreip:
        resultado_ok("Localhost (127.0.0.1) IPv4 en whitelist")
    else:
        resultado_warn("Localhost (127.0.0.1) no está en la whitelist.")

    if "::1" in ignoreip:
        resultado_ok("Localhost (::1) IPv6 en whitelist.")
    else:
        resultado_warn("Localhost (::1) IPv6 no está en la whitelist.")

    # Verificar si hay IPs adicionales (aparte de localhost)
    ips=ignoreip.split()
    ipsExtra=[ip for ip in ips if ip not in ("127.0.0.1/8", "127.0.0.1", "::1")]
    if ipsExtra:
        resultado_ok(f"IPs adicionales en whitelist: {', '.join(ipsExtra)}")
    else:
        resultado_warn("Solo localhost en whitelist. Considerar añadir IPs de administración para evitar\n" \
        "       bloqueos accidentales.")


def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    print()
    print("="*100)
    print("[AUDITORÍA MÓDULO 13]: Fail2Ban")
    print("="*100)
    print()

    print()
    print("     Comprobando configuraciones de los pasos 1 al 5...")
    print()

    verificar_paso1()
    verificar_paso2()
    verificar_paso3()
    verificar_paso4()
    verificar_paso5()


    mostrar_resumen("fix_mod13.py")

    if contadores["checksFail"]>0:
        sys.exit(1)
    else:
        sys.exit(0)

# =============================================================================
if __name__ == "__main__":
    main()
