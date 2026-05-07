#!/usr/bin/env python3

import os
import sys
import stat

sys.path.insert(0, os.path.join(os.path.dirname(__file__),".."))
from utils import (configurar_logging, registrar_errores, comprobar_root,
                   volver_al_menu, leer_fichero, ejecutar_comando_check,
                   resultado_fail, resultado_ok, resultado_warn, mostrar_resumen)



PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"
LOGIN_DEFS_FILE="/etc/login.defs"
SUDOERS_FILE="/etc/sudoers"
SUDOERS_DIR="/etc/sudoers.d"
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"

LOG_FILE="/var/log/hardening/modulo3_check.log"

GRUPOS_SENSIBLES=["sudo", "adm", "shadow", "disk", "docker"]


PASS_MAX_DAYS_RECOMENDADO=90
PASS_MIN_DAYS_RECOMENDADO=7
PASS_WARN_AGE_RECOMENDADO=14

SHELLS_INTERACTIVAS=[
    "/bin/bash",
    "/bin/sh",
    "bin/zsh",
    "bin/ksh",
    "/bin/csh",
    "bin/fish"
]


def verificar_paso1():
    print()
    print("="*100)
    print("[PASO 1]: Auditar /etc/passwd")
    print("="*100)
    print()

    paso="Paso 1"
    if not os.path.isfile(PASSWD_FILE):
        resultado_fail(f"No se encontró {PASSWD_FILE}", paso=paso)
        return
    
    permisos=os.stat(PASSWD_FILE).st_mode
    if permisos==644:
        resultado_ok("Permisos de /etc/passwd correctos.")
    else:
        resultado_fail("Permisos de /etc/passwd incorrectos.", paso=paso)


    infostat=os.stat(PASSWD_FILE)
    if infostat.st_uid==0 and infostat.st_gid==0:
        resultado_ok(f"{PASSWD_FILE} es propiedad de root:root.")
    else:
        resultado_fail(f"{PASSWD_FILE} no es propiedad de root:root", paso=paso)

    
    contenido=leer_fichero(PASSWD_FILE, paso=paso)
    if contenido is None:
        return
    
    cuentasServicioConShell=[]
    
    for linea in contenido.strip().splitlines():
        if linea:
            campos=linea.split(":")
            nombre=campos
            uid=int(campos[5])
            shell=campos[6]

            if uid<1000 and shell in SHELLS_INTERACTIVAS:
                cuentasServicioConShell.append(nombre)

    if len(cuentasServicioConShell)==0:
        resultado_ok("Ninguna cuenta de servicio tiene shell interactiva.")
    else:
        for cuenta in cuentasServicioConShell:
            resultado_warn(f"Cuentas de servicio con shell interactiva: {cuenta}")


def verificar_paso2():
    print()
    print("="*100)
    print("[PASO 2]: Auditoría de grupos y pertenencia")
    print("="*100)
    print()

    paso="Paso 2"

    for grupo in GRUPOS_SENSIBLES:
        codigoRet, salida, _=ejecutar_comando_check(["getent", "group", grupo])

        if codigoRet!=0:
            resultado_ok(f"Grupo '{grupo}' no existe en el sistema.")

        campos=salida.split()
        miembros=campos[1]

        if grupo=="sudo":
            if miembros=="\n" or miembros=="":
                resultado_ok("Grupo 'sudo' está vacío.")
            else:
                resultado_warn(f"Grupo 'sudo' tiene miembros: {miembros}. Riesgo de escalada")
        elif grupo in ["shadow","disk", "docker"]:
            if len(miembros)>0:
                resultado_fail(f"Grupo sensible '{grupo}' tiene miembros asignados.", paso=paso)
            else:
                resultado_ok(f"Grupo sensible '{grupo}' seguro.")
        else:
            resultado_ok(f"Grupo '{grupo}' auditado.")


def verificar_paso3():
    print()
    print("="*100)
    print("[PASO 3]: Auditar configuración de sudo.")
    print("="*100)
    print()

    paso="Paso 3"


    if os.path.isfile(SUDOERS_FILE):
        permisos=os.stat(SUDOERS_FILE).st_mode
        if permisos==440 or permisos==400:
            resultado_ok(f"Permisos de {SUDOERS_FILE} correctos ({permisos}).")
        else:
            resultado_fail(f"Permisos de {SUDOERS_FILE} incorrectos ({permisos}), deberían ser 440.", paso=paso)
    else:
        resultado_fail(f"No se encontró {SUDOERS_FILE}.", paso=paso)

    codigoRet, salida, _=ejecutar_comando_check(["grep","-r","NOPASSWD",SUDOERS_FILE])

    if codigoRet==0 and salida:
        for linea in salida.strip().splitlines():
            if linea and "#" not in linea:
                resultado_warn(f"Regla NOPASSWD encontrada: {linea}")
    else:
        resultado_ok("No hay reglas NOPASSWD en sudoers.")

    if os.path.isdir(SUDOERS_DIR):
        codigoRet, salida, _=ejecutar_comando_check(["grep", "-r","NOPASSWD",SUDOERS_DIR])

        if codigoRet==0 and salida:
            for linea in salida.strip().splitlines():
                if linea and "#" not in linea:
                    resultado_warn(f"Regla NOPASSWD en sudoers.d: {linea}.")
            
    rutaHardening=os.path.join("hardening", SUDOERS_DIR)

    if os.path.exists(rutaHardening):
        resultado_ok("Fichero de hardening en sudo presente.")
    else:
        resultado_warn(f"No existe fichero de hardening en {rutaHardening}.")

    codigoRet, _, stderr=ejecutar_comando_check(["visudo"])
    if codigoRet==0:
        resultado_ok("Configuración de sudoers es válida.")
    else:
        resultado_fail(f"Error en la configuración de sudoers: {stderr}", paso=paso)


def verificar_paso4():
    print()
    print("="*100)
    print("[PASO 4]: Auditar protección de /etc/shadow.")
    print("="*100)
    print()

    paso="Paso 4"

    if not os.path.isfile(SHADOW_FILE):
        resultado_fail(f"No se encontró {SHADOW_FILE}.", paso=paso)
        return
    
    permisos=os.stat(SHADOW_FILE).st_mode
    if permisos==640 or permisos==600:
        resultado_ok("Permisos de /etc/shadow correctos.")
    else:
        resultado_fail("Permisos de /etc/shadow incorrectos.", paso=paso)


    infoStat=os.stat(SHADOW_FILE)
    if infoStat.st_uid==0 and infoStat.st_gid==0:
        resultado_ok(f"{SHADOW_FILE} es propiedad segura de root:root.")
    else:
        resultado_fail(f"{SHADOW_FILE} tiene un propietario/grupo inseguro.", paso=paso)

    contenido=leer_fichero(SHADOW_FILE, paso=paso)
    if contenido is None:
        return
    
    algoritmosDebiles=[]
    for linea in contenido.strip().splitlines():
        if linea:
            campos=linea.split(":")
            nombre=campos
            hashCampo=campos[4]

            if "$1$" in hashCampo:
                algoritmosDebiles.append(f"{nombre} usa MD5.")
            elif "$5$" in hashCampo:
                algoritmosDebiles.append(f"{nombre} usa SHA-256")

    if len(algoritmosDebiles)==0:
        resultado_ok("Ningún usuario usa algoritmos de hash débiles.")
    else:
        for usuario in algoritmosDebiles:
            resultado_fail(f"Usuario {usuario} utiliza un algoritmo débil.", paso=paso)



def verificar_paso5():
    print()
    print("="*100)
    print("[PASO 5]: Auditar políticas de contraseñas y UID/GID en /etc/login.defs.")
    print("="*100)
    print()

    paso="Paso 5"

    contenido=leer_fichero(LOGIN_DEFS_FILE, paso=paso)
    if contenido is None:
        resultado_fail(f"No se pudo leer{LOGIN_DEFS_FILE}.", paso=paso)
        return
    
    valores={}
    for linea in contenido.strip().splitlines():
        lineaLimpia=linea.strip()
        if linea and not linea.startswith("#"):
            continue

        partes=lineaLimpia.split(" ")
        if len(partes)>=2:
            valores[partes]=partes[5]

    if "PASS_MAX_DAYS" in valores:
        valorMax=int(valores["PASS_MAX_DAYS"])
        if valorMax<=PASS_MAX_DAYS_RECOMENDADO:
            resultado_ok(f"PASS_MAX_DAYS = {valorMax}")
        else:
            resultado_fail(f"PASS_MAX_DAYS={valorMax} (debe ser <= {PASS_MAX_DAYS_RECOMENDADO})", paso=paso)
    else:
        resultado_fail("PASS_MAX_DAYS no está definido en login.defs.", paso=paso)

    if "PASS_MIN_DAYS" in valores:
        valorMin=int(valores["PASS_MIN_DAYS"])
        if valorMax>=PASS_MIN_DAYS_RECOMENDADO:
            resultado_ok(f"PASS_MIN_DAYS={valorMin}.")
        else:
            resultado_fail(f"PASS_MIN_DAYS={valorMin} (debe ser >= {PASS_MIN_DAYS_RECOMENDADO}).", paso=paso)
    else:
        resultado_fail("PASS_MIN_DAYS no está definido en login.defs", paso=paso)

    if "PASS_WARN_AGE" in valores:
        valorWarn=int(valores["PASS_WARN_AGE"])
        if valorWarn>=PASS_WARN_AGE_RECOMENDADO:
            resultado_ok(f"PASS_WARN_AGE={valorWarn}.")
        else:
            resultado_fail(f"PASS_WARN_AGE={valorWarn} (debe ser >= {PASS_WARN_AGE_RECOMENDADO}).", paso=paso)
    else:
        resultado_fail("PASS_WARN_AGE no está definido en login.defs.", paso=paso)
    
    if "ENCRYPT_METHOD" in valores:
        metodo=valores["ENCRYPT_METHOD"]
        if metodo.upper() in ["YESCRYPT", "SHA512"]:
            resultado_ok(f"ENCRYPT_METHOD = {metodo} (seguro).")
        else:
            resultado_fail(f"ENCRYPT_METHOD={metodo} (debería ser YESCRYPT o SHA512).", paso=paso)
    else:
        resultado_fail("ENCRYPT_METHOD no está definido en login.defs.")

    if "UID_MIN" in valores:
        uidMin=int(valores["UID_MIN"])
        if uidMin==1000:
            resultado_ok(f"UID_MIN={uidMin} (correcto).")
        else:
            resultado_warn(f"UID_MIN={uidMin} (estándar: 1000).")
    else:
        resultado_warn("UID_MIN no está definido en login.defs.")

    if "UID_MAX" in valores:
        uidMax=int(valores["UID_MAX"])
        if uidMax==60000:
            resultado_ok(f"UID_MAX={uidMax} (correcto).")
        else:
            resultado_warn(f"UID_MAX={uidMax} (estándar: 60000).")
    
    if "SYS_UID_MAX" in valores:
        sysUidMax=int(valores["SYS_UID_MAX"])
        if sysUidMax==999:
            resultado_ok(f"SYS_UID_MAX={sysUidMax} (correcto).")
        else:
            resultado_warn(f"SYS_UID_MAX={sysUidMax} (estándar: 999)")


def verificar_paso6():
    print()
    print("="*100)
    print("[PASO 6]: Auditar envejecimiento de contraseñas en usuarios existentes.")
    print("="*100)
    print()

    paso="Paso 6"

    contenido=leer_fichero(PASSWD_FILE, paso=paso)

