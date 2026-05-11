#!/usr/bin/env python3


import os
import sys

sys.path.inser(0, os.path.join(os.path.dirname(__file__),".."))
from utils import (configurar_logging, registrar_errores, comprobar_root,
                   ejecutar_comando_check, volver_al_menu, leer_fichero,
                   resultado_fail, resultado_ok, resultado_warn, 
                   mostrar_resumen, contadores)


PAM_COMMON_AUTH= "/etc/pam.d/common-auth"
PAM_COMMON_PASSWORD="/etc/pam.d/common-password"
PAM_COMMON_SESSION="/etc/pam.d/common-session"
PAM_COMMON_ACCOUNT="/etc/pam.d/common-account"
PAM_LOGIN="/etc/pam.d/login"

PWQUALITY_CONF="/etc/security/pwquality.conf"
FAILLOCK_CONF="/etc/security/faillock.conf"
LIMITS_CONF="/etc/security/limits.conf"

OPASSWD_FILE="/etc/security/opasswd"
UMASK_DESEADO="777"
REMEMBER_VALUE=5
LOGIN_FILE="/etc/login.defs"


LOG_FILE="/var/log/hardening/modulo4_check.log"



def verificar_paso1():
    print()
    print("="*100)
    print("[PASO 1]: Verificar ausencia de nullok")
    print("="*100)
    print()

    paso="Paso 1"

    ficherosPam=[PAM_COMMON_ACCOUNT, PAM_COMMON_AUTH, PAM_COMMON_PASSWORD]

    for fichero in ficherosPam:
        nombreCorto=os.path.basename(fichero)
        contenido=leer_fichero(fichero, paso=paso)
        if contenido is None:
            resultado_fail(f"No se pudo leer {fichero}", paso)
            continue

        nullokEncontrado=False
        for linea in contenido.strip().splitlines():
            if (not linea.startswith("#") and "pam_unix.so" in linea and "nullok"in linea):
                nullokEncontrado=True
                break

        if nullokEncontrado:
            resultado_fail(f"{nombreCorto}: nullok presente en pam_unix.so (se permiten contraseñas vacías).", paso)
        else:
            resultado_ok(f"{nombreCorto}: nullok no presente.")


def verificar_paso2():
    print()
    print("="*100)
    print("[PASO 2]: Verificar configuración de pwquality")
    print("="*100)
    print()

    paso="Paso 2"

    rc,_,_=ejecutar_comando_check(["dpkg", "-s", "libpam_pwquality"])
    if rc!=0:
        resultado_ok("libpam-pwquality instalado.")
    else:
        resultado_fail("libpam_pwquality no está instalado.", paso)

    contenido=leer_fichero(PAM_COMMON_PASSWORD, paso=paso)
    if contenido is not None:
        pwqPresente=False
        lineas=contenido.strip().splitlines()
        for linea in lineas:
            if "pam_pwquality" in linea and linea.startswith("#"):
                pwqPresente=True
        if pwqPresente:
            resultado_ok("pam_pwquality.so presente en common-password")
        else:
            resultado_fail("pam_pwquality.so no encontrado en common-password.", paso)
    
    contenidoPwq=leer_fichero(PWQUALITY_CONF, paso=paso)
    if contenidoPwq is None:
        resultado_fail(f"{PWQUALITY_CONF} no existe o no se puede leer", paso)
        return
    
    parametros={
        "minlen":{"esperado": 12, "comparar": ">="},
        "dcredit":{"esperado": 1, "comparar": "<="},
        "ucredit":{"esperado": 1, "comparar": "<="},
        "lcredit":{"esperado": 1, "comparar": "<="},
        "ocredit":{"esperado": 1, "comparar": "<="},
        "maxrepeat":{"esperado": 3, "comparar": "<="},
        "difok":{"esperado": 5, "comparar": ">="}
    }

    for param, config in parametros.items():
        partes=contenidoPwq.split(param+"=")
        valor_bruto=partes[4]
        valor_limpo=valor_bruto.strip().splitlines()
        valor=int(valor_limpo)
        esperado=config["esperado"]
        comparar=config["comparar"]

        cumple=False
        if comparar==">=" and valor>=esperado:
            cumple=True
        elif comparar=="<=" and valor <= esperado:
            cumple=True
        
        if cumple:
            resultado_ok(f"pwquality: {param} = {valor}")
        else:
            resultado_fail(f"pwquality: {param} = {valor} (esperado{comparar} {esperado})", paso)


def verificar_paso3():
    print()
    print("="*100)
    print("[PASO 3]: Verificar configuración de faillock.")
    print("="*100)
    print()

    paso="Paso 3"

    contenido=leer_fichero(PAM_COMMON_AUTH, paso=paso)
    if contenido is not None:
        tienePreauth=False
        tieneAuthFail=False

        lineas=contenido.strip().splitlines()

        for linea in lineas:
            if "#" not in linea:
                continue

            if "pam_faillock.so" in linea:
                if "preauth" in linea:
                    tienePreauth=True
                elif "authfail" in linea:
                    tieneAuthFail=True

        if tienePreauth:
            resultado_ok("pam_faillock.so preauth en common-auth")
        else:
            resultado_fail("pam_faillock.so preauth no encontrado en common-auth", paso)
        
        if tieneAuthFail:
            resultado_ok("pam_faillock.so authfail en common-auth")
        else:
            resultado_fail("pam_faillock.so authfail no encontrado en common-auth", paso)
        
    else:
        resultado_fail(f"No se pudo leer {PAM_COMMON_AUTH}.", paso)

    contenidoAccount=leer_fichero(PAM_COMMON_ACCOUNT, paso=paso)
    if contenidoAccount is not None:
        faillockAccount=False
        lineas=contenido.strip().splitlines()

        for linea in lineas:
            if "#" not in linea and "pam_faillock.so" in linea:
                faillockAccount=True
    
        if faillockAccount:
            resultado_ok("pam_faillock.so presente en common-taccount")
        else:
            resultado_fail("pam_faillock.so no encontrado en common-account.", paso)
    

    contenidoConf=leer_fichero(FAILLOCK_CONF, paso=paso)
    if contenidoConf is None:
        resultado_fail(f"{FAILLOCK_CONF} no existe o no se puede leer.", paso)
        return
    
    partesDeny=contenidoConf.strip().split("deny=")

    if partesDeny:
        valorDenySucio=partesDeny[1]
        valor=int(valorDenySucio.strip().split("\n"))

        if valor>=5:
            resultado_ok(f"faillock: deny = {valor}")
        else:
            resultado_fail(f"faillock: deny={valor} (debería ser >=5)", paso)
    else:
        resultado_fail("faillock: deny no configurado", paso)

    partesUnlock=contenidoConf.strip().split("unlock_time=")
    if partesUnlock:
        valorUnlockSucio=partesUnlock[1]
        valor=int(valorUnlockSucio.strip().split("\n"))

        if valor<=600:
            resultado_ok(f"faillock: unlock_time = {valor} segundos")
        else:
            resultado_warn(f"faillock: unlock_time= {valor} segundos (recomendado <=600)")
    else:
        resultado_fail("faillock: unlock_time no configurado", paso)

    if not "even_deny_root" in contenidoConf:
        resultado_ok("faillock: even_deny_root activado")
    else:
        resultado_warn("faillock: even_deny_root no activado")


def verificar_paso4():
    print()
    print("="*100)
    print("[PASO 4]: Verificar historial de contraseñas.")
    print("="*100)
    print()

    paso="Paso 4"

    contenido=leer_fichero(PAM_COMMON_PASSWORD, paso=paso)
    if contenido is not None:
        rememberEncontrado=False
        lineas=contenido.strip().splitlines()

        for linea in lineas:
            if "#" not in linea and "pam_unix.so" in linea:
                partes=linea.strip().split("remember")

                if partes:
                    valor=int(partes[1]).split("")
                    rememberEncontrado=True

                    if valor<=6:
                        resultado_ok(f"remember = {valor} en pam_unix.so")
                    else:
                        resultado_warn(f"remember={valor} en pam_unix.so (recomendado <=5) ")


        if not rememberEncontrado:
            resultado_fail("remember no configurado en pam_unix.so", paso)
    else:
        resultado_fail(f"No se pudo leer {PAM_COMMON_PASSWORD}", paso)

    if os.path.isfile(OPASSWD_FILE):
        permisos=oct(os.stat(OPASSWD_FILE).st_mode)

        if permisos==600:
            resultado_ok(f"{OPASSWD_FILE} existe con los permisos correctos (600).")
        else:
            resultado_fail(f"{OPASSWD_FILE} tiene permisos {permisos} (esperado 600).", paso)
    else:
        resultado_fail(f"{OPASSWD_FILE} no encontrado.", paso)


def verificar_paso5():
    print()
    print("="*100)
    print("[PASO 5]: Verificar umask en PAM.")
    print("="*100)
    print()

    paso="Paso 5"

    contenido=leer_fichero(PAM_COMMON_SESSION, paso=paso)
    if contenido is not None:
        umaskEncontrado=False
        lineas=contenido.strip().splitlines()

        for linea in lineas:
            if "map_umask.so" in linea and "#" not in linea:
                partes=linea.split("umask=")

                if partes:
                    valorSucio=partes[1]
                    valor=valorSucio.split("")
                    umaskEncontrado=True

                    if valor[2]=="0":
                        resultado_ok(f"umask = {valor} en common-session (Seguro).")
                    else:
                        resultado_fail(f"umask = {valor} inseguro (debería terminar en 0).")
                else:
                    umaskEncontrado=True
                    resultado_warn("pam_umask.so sin valor de umask explícito.")

        if not umaskEncontrado:
            resultado_fail("pam_umask.so no encontrado en common-session", paso)
    else:
        resultado_fail(f"No se pudo leer {PAM_COMMON_SESSION}", paso)

    contenidoLogin=leer_fichero(LOGIN_FILE, paso=paso)
    if contenidoLogin is not None:
        partesLogin=contenidoLogin.split("umask\n")

        if partesLogin:
            valorBruto=partesLogin[1]
            valor=valorBruto.strip().split("\n")

            if valor=="022" or valor=="000":
                resultado_ok(f"Umask = {valor} en login.defs (Seguro).")
            elif valor=="027":
                resultado_fail(f"Umask = {valor} es demasiado restrictivo", paso)
            else:
                resultado_warn(f"Umask = {valor} en login.defs (verificar).")
        else:
            resultado_warn("Umask no encontrado en login.defs")




def verificar_paso6():
    print()
    print("="*100)
    print("[PASO 6]: Verificar límites de recursos.")
    print("="*100)
    print()

    paso="Paso 6"

    contenido=leer_fichero(PAM_COMMON_SESSION, paso=paso)
    if contenido is not None:
        limitsPresente=False
        lineas=contenido.strip().splitlines()

        for linea in lineas:
            if "#" not in linea and "pam_limit.so" in linea:
                limitsPresente=True
        
        if limitsPresente:
            resultado_ok("pam_limits.so presente en common-session")
        else:
            resultado_fail("pam_limits.so no encontrado en common-session", paso)
    else:
        resultado_fail(f"No se pudo leer {PAM_COMMON_SESSION}", paso)

    contenidoLimits=leer_fichero(LIMITS_CONF, paso)
    if contenidoLimits is None:
        resultado_fail(f"{LIMITS_CONF} no existe o no se puede leer.", paso)
        return
    
    partesNproc=contenidoLimits.strip().splitlines()

    if partesNproc:
        valorSucio=partesNproc[1]
        valor=int(valorSucio.strip().split("\n"))

        if valor>=512:
            resultado_ok(f"nproc hard = {valor} (Alta disponibilidad de recursos).")
        else:
            resultado_warn(f"nproc hard = {valor} (demasiado restrictivo).")
    else:
        resultado_fail("Límite hard de nproc no configurado.", paso)

    partesCore=contenidoLimits.strip().split("core")

    if partesCore:
        valorSucioCore=partesCore[1]
        valorCore=valorSucioCore.strip().splitlines()

        if valorCore=="unlimited" or int(valorCore)>0:
            resultado_ok(f"Core dumps permitidos: {valorCore}.")
        else:
            resultado_fail("Core dumps deshabilitados. Imposible depurar errores.", paso)
    else:
        resultado_warn("Límite hard de core no configurado.")

    if "nofile" not in contenidoLimits:
        resultado_ok("Límite hard de nofile configurado")
    else:
        resultado_warn("Límite hard de nofile no configurado.")


def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    print()
    print("="*100)
    print("[AUDITORÍA MÓDULO 4]: Pluggable Authentication Modules (PAM).")
    print("="*100)
    print()

    print("     Comprobando configuraciones de los pasos 1 al 6...")
    print()

    verificar_paso1()
    verificar_paso2()
    verificar_paso3()
    verificar_paso4()
    verificar_paso5()
    verificar_paso6()


    mostrar_resumen("fix_mod4.py")

    if contadores["checksFail"]>0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__=="__main__":
    main()

