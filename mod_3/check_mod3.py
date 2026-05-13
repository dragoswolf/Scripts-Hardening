#!/usr/bin/env python3

import os
import sys
import stat

sys.path.insert(0, os.path.join(os.path.dirname(__file__),".."))
from utils import (configurar_logging, registrar_errores, comprobar_root,
                   leer_fichero, ejecutar_comando_check, resultado_fail, 
                   resultado_ok, resultado_warn, mostrar_resumen,
                   contadores, verificar_permisos)



PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"
LOGIN_DEFS_FILE="/etc/login.defs"
SUDOERS_FILE="/etc/sudoers"
SUDOERS_DIR="/etc/sudoers.d"
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"

LOG_FILE="/var/log/hardening/modulo3_check.log"

GRUPOS_SENSIBLES=["root", "sudo", "adm", "shadow", "disk", "docker"]


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
    
    verificar_permisos(PASSWD_FILE, "644", 0, 0, paso=paso)
    
    contenido=leer_fichero(PASSWD_FILE, paso=paso)
    if contenido is None:
        return
    
    cuentasServicioConShell=[]
    
    for linea in contenido.strip().splitlines():
        campos=linea.split(":")
        if len(campos)!=7:
            resultado_warn(f"Línea mal formada en passwd: {linea}")
            continue
        nombre=campos[0]
        uid=int(campos[2])
        shell=campos[6]

        if 0<uid<1000 and shell in SHELLS_INTERACTIVAS:
            cuentasServicioConShell.append(f"{nombre} (UID={uid}, shell={shell})")

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

        if codigoRet==0:
            campos=salida.strip().split(":")
            miembros=campos[3] if len(campos)>3 and campos[3] else "(sin miembros explícitos)"

            if grupo=="sudo":
                resultado_ok(f"Grupo '{grupo}' - miembros: {miembros}")
            elif grupo in ["shadow","disk", "docker"]:
                if len(campos) >3 and campos[3]:
                    resultado_warn(f"Grupo sensible '{grupo}' tiene miembros asignados ({miembros}).")
                else:
                    resultado_ok(f"Grupo sensible '{grupo}' sin miembros explícitos.")
            else:
                resultado_ok(f"Grupo '{grupo}' auditado.")
        else:
            resultado_ok(f"Grupo '{grupo}' no existe en el sistema.")


def verificar_paso3():
    print()
    print("="*100)
    print("[PASO 3]: Auditar configuración de sudo.")
    print("="*100)
    print()

    paso="Paso 3"


    verificar_permisos(SUDOERS_FILE, ["440", "400"], paso=paso)

    codigoRet, salida, _=ejecutar_comando_check(["grep","-r","NOPASSWD",SUDOERS_FILE])

    if codigoRet==0 and salida.strip():
        for linea in salida.strip().splitlines():
            if not linea.strip().startswith("#"):
                resultado_warn(f"Regla NOPASSWD encontrada: {linea.strip()}")
    else:
        resultado_ok("No hay reglas NOPASSWD en sudoers.")

    if os.path.isdir(SUDOERS_DIR):
        codigoRet, salida, _=ejecutar_comando_check(["grep", "-r","NOPASSWD",SUDOERS_DIR])

        if codigoRet==0 and salida.strip():
            for linea in salida.strip().splitlines():
                if not linea.strip().startswith("#"):
                    resultado_warn(f"Regla NOPASSWD en sudoers.d: {linea.strip()}.")
            
    rutaHardening=os.path.join("hardening", SUDOERS_DIR)

    if os.path.exists(rutaHardening):
        resultado_ok("Fichero de hardening en sudo presente.")
    else:
        resultado_warn(f"No existe fichero de hardening en {rutaHardening}.")

    if os.geteuid()==0:
        codigoRet, _, stderr=ejecutar_comando_check(["visudo", "-c"])
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
    
    verificar_permisos(SHADOW_FILE, ["640", "600"], 0, paso=paso)

    infoStat=os.stat(SHADOW_FILE)
    if infoStat.st_uid==0:
        resultado_ok(f"{SHADOW_FILE} es propiedad segura de root:root.")
    else:
        resultado_fail(f"{SHADOW_FILE} no es propiedad de root (UID = {infoStat.st_uid}).", paso=paso)

    contenido=leer_fichero(SHADOW_FILE, paso=paso)
    if contenido is None:
        return
    
    algoritmosDebiles=[]
    for linea in contenido.strip().splitlines():
        campos=linea.split(":")
        if len(campos)<2:
            continue
        hashCampo=campos[1]
        nombre=campos[0]

        if hashCampo.startswith("$1$"):
            algoritmosDebiles.append(f"{nombre} usa MD5.")
        elif hashCampo.startswith("$5$"):
            algoritmosDebiles.append(f"{nombre} usa SHA-256.")

    if len(algoritmosDebiles)==0:
        resultado_ok("Ningún usuario usa algoritmos de hash débiles.")
    else:
        for alerta in algoritmosDebiles:
            resultado_fail(alerta, paso=paso)



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
    for linea in contenido.splitlines():
        lineaLimpia=linea.strip()
        if lineaLimpia.startswith("#") or not lineaLimpia:
            continue

        partes=lineaLimpia.split()
        if len(partes)>=2:
            valores[partes[0]]=partes[1]

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
    if contenido is None:
        return
    
    usuariosHumanos=[]
    for linea in contenido.strip().splitlines():
        campos=linea.split(":")
        if len(campos)==7:
            uid=int(campos[2])
            if 1000<= uid < 65534:
                usuariosHumanos.append(campos[0])

    if not usuariosHumanos:
        resultado_warn("No se encontraron usuarios humanos (UID >= 1000).")
        return
    
    for usuario in usuariosHumanos:
        codigoRet, salida, _=ejecutar_comando_check(["chage","-l", usuario])
        if codigoRet!=0:
            resultado_fail(f"No se pudo consultare chage para {usuario}.", paso=paso)
            continue

        maxDias=None
        minDias=None
        warnDias=None

        for linea in salida.splitlines():
            if "Maximum number of days" in linea:
                valor=linea.split(":")[-1].strip()
                try:
                    maxDias=int(valor)
                except ValueError:
                    maxDias=None
            elif "Minimum number of days" in linea:
                valor=linea.split(":")[-1].strip()
                try:
                    minDias=int(valor)
                except ValueError:
                    minDias=None
            elif "Number of days of warning" in linea:
                valor=linea.split(":")[-1].strip()
                try:
                    warnDias=int(valor)
                except ValueError:
                    warnDias=None

        if maxDias is not None:
            if maxDias<=PASS_MAX_DAYS_RECOMENDADO and maxDias>0:
                resultado_ok(f"{usuario}: PASS_MAX_DAYS = {maxDias}.")
            elif maxDias==99999 or maxDias<=0:
                resultado_fail(f"{usuario}: contraseña nunca expira (MAX_DAYS={maxDias}).", paso=paso)
            else:
                resultado_warn(f"{usuario}: PASS_MAX_DAYS={maxDias} (recomendado <= {PASS_MAX_DAYS_RECOMENDADO}).")


def verificar_paso7():
    print()
    print("="*100)
    print("[PASO 7]: Auditar cuentas sin contraseña deshabilitadas.")
    print("="*100)
    print()

    paso="Paso 7"

    contenido=leer_fichero(SHADOW_FILE, paso=paso)
    if contenido is None:
        return
    
    cuentasSinPasswd=[]

    for linea in contenido.strip().splitlines():
        campos=linea.split(":")
        if len(campos) >=2 and campos[1]=="":
            cuentasSinPasswd.append(campos[0])

    if len(cuentasSinPasswd)==0:
        resultado_ok("No hay cuentas con contraseña vacía.")
    else:
        for cuenta in cuentasSinPasswd:
            resultado_fail(f"Cuenta sin contraseña: {cuenta}", paso=paso)

    contenidoSsh=leer_fichero(SSHD_CONFIG_FILE, paso=paso)
    if contenidoSsh is not None:
        encontrado=False

        for linea in contenidoSsh.splitlines():
            lineaLimpia=linea.strip()
            if lineaLimpia.startswith("#"):
                continue
            if "PermitEmptyPasswords" in lineaLimpia:
                encontrado=True
                if "no" in lineaLimpia.lower():
                    resultado_ok("SSH: PermitEmptyPasswords = no.")
                else:
                    resultado_fail("SSH: PermitEmptyPasswords no está en 'no'.", paso=paso)
                break

        if not encontrado:
            resultado_warn("SSH: PermitEmptyPasswords no está definido (por defecto es 'no').")

    
def verificar_paso8():
    print()
    print("="*100)
    print("[PASO 8]: Auditar usuarios no-root con UID 0.")
    print("="*100)
    print()

    paso="Paso 8"

    contenido=leer_fichero(PASSWD_FILE, paso=paso)
    if contenido is None:
        return
    
    cuentasUid0=[]

    for linea in contenido.strip().splitlines():
        campos=linea.split(":")
        if len(campos)==7 and campos[2] =="0":
            cuentasUid0.append(campos[0])

    if cuentasUid0==["root"]:
        resultado_ok("Solo 'root' tiene UID 0.")
    elif "root" in cuentasUid0:
        cuentasUid0.remove("root")
        for cuenta in cuentasUid0:
            resultado_fail(f"Cuenta con UID 0 detectada: {cuenta} (posible backdoor).", paso=paso )
    else:
        resultado_fail("No se encontró la cuenta root con UID 0.", paso=paso)


def verificar_paso9():
    print()
    print("="*100)
    print("[PASO 9]: Auditar bloqueo automático de cuentas inactivas.")
    print("="*100)
    print()

    paso="Paso 9"

    codigoRet, salida, _=ejecutar_comando_check(["useradd", "-D"])

    if codigoRet==0:
        for linea in salida.splitlines():
            if "INACTIVE" in linea:
                valor=linea.split("=")[-1].strip()
                if valor=="-1":
                    resultado_fail("INACTIVE = -1 (cuentas nunca se bloquean por inactividad).", paso=paso)
                else:
                    try:
                        diasInactivo=int(valor)
                        if 0<diasInactivo<=30:
                            resultado_ok(f"INACTIVE = {diasInactivo} días (cuentas se bloquean tras inactividad).")
                        elif diasInactivo>30:
                            resultado_warn(f"INACTIVE = {diasInactivo} días (recomendado <= 30)")
                        else:
                            resultado_fail(f"INACTIVE = {valor} (valor no válido).", paso=paso)
                    except ValueError:
                        resultado_warn(f"INACTIVE = {valor} (no se pudo interpretar el valor).")
                break


def verificar_paso10():
    print()
    print("="*100)
    print("[PASO 10]: Auditar restricción al acceso directo a root.")
    print("="*100)
    print()

    paso="Paso 10"

    codigoRet, salida, _=ejecutar_comando_check(["passwd", "-S", "root"])

    if codigoRet==0:
        partes=salida.strip().split()
        if len(partes)>=2:
            estado=partes[1]
            if estado=="L":
                resultado_ok("Contraseña de root bloqueada (estado L).")
            elif estado=="P":
                resultado_warn("Root tiene contraseña activa (estado P). Se recomienda bloquearla.")
            else:
                resultado_warn(f"Estado de root: {estado}.")

    contenidoSsh=leer_fichero(SSHD_CONFIG_FILE, paso=paso)
    
    if contenidoSsh is not None:
        encontrado=False

        for linea in contenidoSsh.splitlines():
            lineaLimpia=linea.strip()
            if linea.startswith("#"):
                continue
            if "PermitRootLogin" in lineaLimpia:
                encontrado=True
                
                if "no" in lineaLimpia.lower().split():
                    resultado_ok("SSH: PermitRootLogin = no.")
                elif "prohibit-password" in lineaLimpia.lower():
                    resultado_warn("SSH: PermitRootLogin = prohibit-password (mejor que 'yes', pero se recomienda 'no').")
                else:
                    resultado_fail("SSH: PermitRootLogin no está en 'no'", paso=paso)
                break
                

    if not encontrado:
        resultado_warn("SSH: PermitRootLogin no está definido (por defecto permite login).")

    codigoRet, salida, _=ejecutar_comando_check(["getent", "group", "sudo"])
    
    if codigoRet==0:
        campos=salida.strip().split(":")
        miembros=campos[3] if len(campos) >3 and campos[3] else ""
        if miembros:
            resultado_ok(f"Grupo sudo tiene miembros: {miembros} (acceso privilegiado garantizado).")
        else:
            resultado_fail("Grupo sudo sin miembros. Si 'root' está bloqueado, no hay acceso privilegiado.", paso=paso)


def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    print()
    print("="*100)
    print("[AUDITORÍA MÓDULO 3]: Seguridad en Usuarios y Grupos.")
    print("="*100)
    print()

    print("     Comprobando configuraciones de los pasos 1 al 10...")
    print()

    verificar_paso1()
    verificar_paso2()
    verificar_paso3()
    verificar_paso4()
    verificar_paso5()
    verificar_paso6()
    verificar_paso7()
    verificar_paso8()
    verificar_paso9()
    verificar_paso10()

    mostrar_resumen("fix_mod3.py")

    if contadores["checksFail"]>0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__=="__main__":
    main()

