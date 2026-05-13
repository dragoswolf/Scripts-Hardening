#!/usr/bin/env python3
#=========================================================================================================
# check_mod5.py - Script de verificación para el módulo 5 - SSH (Secure Shell)
#=========================================================================================================
# Este script implementa las siguientes medidas de seguridad:
#
#   Paso 1: Verificar el puerto SSH
#   Paso 2: Verificar acceso por usuarios (AllowUsers/DenyUsers)
#   Paso 3: Verificar autenticación GSSAPI
#   Paso 4: Verificar LoginGraceTime
#   Paso 5: Verificar ClientAliveInterval y ClientAliveCountMax
#   Paso 6: Verificar HostbasedAuthentication
#   Paso 7: Verificar IgnoreRhosts
#   Paso 8: Verificar StrictModes
#   Paso 9: Verificar PermitUserEnvironment
#   Paso 10: Verificar PrintLastLog
#
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo5_check.log
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================
import os
import sys
import re

sys.path.inser(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, 
                   comprobar_root, 
                   volver_al_menu,
                   leer_fichero, 
                   mostrar_resumen, 
                   resultado_fail, 
                   resultado_ok, 
                   resultado_warn, 
                   contadores, 
                   verificar_permisos
                   )


SSHD_CONFIG="/etc/ssh/sshd_config"

LOG_FILE="/var/log/hardening/modulo5_check.log"

#Función auxiliar
def obtener_directiva_ssh(directiva, contenido):
    for linea in contenido.splitlines():
        lineaLimpia=linea.strip()
        if lineaLimpia.startswith("#") or not lineaLimpia:
            continue

        if re.match(rf"^{directiva}\s", lineaLimpia, re.IGNORECASE):
            partes=lineaLimpia.split(None, 1)
            if len(partes)>=2:
                return partes[1]
            return None
    return None


#Medidas de seguridad
def verificar_paso1(contenido):
    print()
    print("="*100)
    print("[PASO 1]: Verificar el puerto SSH.")
    print("="*100)
    print()

    paso="Paso 1"

    puerto=obtener_directiva_ssh("Port", contenido)

    if puerto is None:
        resultado_warn("Puerto SSH no configurado explícitamente (por defecto es 22).")
    elif puerto=="22":
        resultado_warn("Puerto SSH es 22 (estándar). Se recomienda cambiarlo a un puerto no estándar.")
    else:
        try:
            puertoNum=int(puerto)
            if 1024<=puertoNum<=65535:
                resultado_ok(f"Puerto SSH: {puerto} (no estándar, correcto).")
            else:
                resultado_warn(f"Puerto SSH: {puerto} (fuera del rango, recomendado 1024-65535)")
        except ValueError:
            resultado_fail(f"Puerto SSH tiene un valor inválido: {puerto}", paso)


def verificar_paso2(contenido):
    print()
    print("="*100)
    print("[PASO 2]: Verificar AllowUsers.")
    print("="*100)
    print()

    paso="Paso 2"

    allowUsers=obtener_directiva_ssh("AllowUsers", contenido)
    denyUsers=obtener_directiva_ssh("DenyUsers", contenido)

    if allowUsers:
        resultado_ok(f"AllowUsers configurado: {allowUsers}")
    elif denyUsers:
        resultado_ok(f"DenyUsers configurado: {denyUsers}")
    else:
        resultado_warn("AllowUsers/DenyUsers no configurado. Todos los usuarios pueden conectarse por SSH.")


def verificar_paso3(contenido):
    print()
    print("="*100)
    print("[PASO 3]: Verificar GSSAPI deshabilitado.")
    print("="*100)
    print()

    paso="Paso 3"

    valor=obtener_directiva_ssh("GSSAPIAuthentication", contenido)

    if valor is None:
        resultado_warn("GSSAPIAuthentication no configurado explícitamente.")
    elif valor.lower()=="no":
        resultado_ok("GSSAPIAuthentication = no")
    else:
        resultado_fail("GSSAPIAuthentication = yes (debería ser 'no').", paso)


def verificar_paso4(contenido):
    print()
    print("="*100)
    print("[PASO 4]: Verificar LoginGraceTime.")
    print("="*100)
    print()

    paso="Paso 4"

    valor=obtener_directiva_ssh("LoginGraceTime", contenido)

    if valor is None:
        resultado_warn("LoginGraceTime no configurado. Por defecto: 120s")
    else:
        segundos=None
        if valor.endswith("m"):
            try:
                segundos=int(valor[:-1])*60
            except ValueError:
                pass
        elif valor.endswith("s"):
            try:
                segundos=int(valor[:-1])
            except ValueError:
                pass
        else:
            try:
                segundos=int(valor)
            except ValueError:
                pass
        
        if segundos is None:
            resultado_warn(f"LoginGraceTime={valor} (no se pudo interpretar).")
        elif segundos<=60:
            resultado_ok(f"LoginGraceTime = {valor} ({segundos} s)")
        elif segundos <=120:
            resultado_warn(f"LoginGraceTime = {valor} ({segundos} s), recomendado <=60")
        else:
            resultado_fail(f"LoginGraceTime = {valor} ({segundos} s), demasiado alto.", paso)



def verificar_paso5(contenido):
    print()
    print("="*100)
    print("[PASO 5]: Verificar ClientAliveInterval y ClientAliveCountMax.")
    print("="*100)
    print()

    paso="Paso 5"

    intervalo=obtener_directiva_ssh("ClientAliveInterval", contenido)

    if intervalo is None:
        resultado_warn("ClientAliveInterval no configurado (por defecto: 0 = sin timeout).")
    else:
        try:
            valorInt=int(intervalo)
            if 1<=valorInt<=300:
                resultado_ok(f"ClientAliveInterval = {valorInt}")
            elif valorInt==0:
                resultado_fail("ClientAliveInterval = 0 (sin timeout de inactividad).", paso)
            else:
                resultado_warn(f"ClientAliveInterval = {valorInt} (recomendado: 300)")
        except ValueError:
            resultado_warn(f"ClientAliveInterval = {intervalo} (valor no numérico).")
    
    countMax=obtener_directiva_ssh("ClientAliveCountMax", contenido)

    if countMax is None:
        resultado_warn("ClientAliveCountMax no configurado (por defecto. 3)")
    else:
        try:
            valorMax=int(countMax)
            if 1<=valorMax<=3:
                resultado_ok(f"ClientAlive")
            elif valorMax == 0:
                resultado_fail("ClientAliveCountMax = 0 (desconexión inmediata sin aviso)", paso)
            else:
                resultado_warn(f"ClientAliveCountMax = {valorMax} (recomendado: <= 3)")
        except ValueError:
            resultado_warn(f"ClientAliveCountMax = {countMax} (valor no numérico)")


def verificar_paso6(contenido):
    print()
    print("="*100)
    print("[PASO 6]: Verificar HostbasedAuthentication.")
    print("="*100)
    print()

    paso="Paso 6"

    valor=obtener_directiva_ssh("HostbasedAuthentication", contenido)

    if valor is None:
        resultado_ok("HostbasedAuthentication no configurado (por defecto: no)")
    elif valor.lower()=="no":
        resultado_ok("HostbasedAuthentication = no")
    else:
        resultado_fail("HostbasedAuthentication = yes (autenticación basada en host habilitada)", paso)


def verificar_paso7(contenido):
    print()
    print("="*100)
    print("[PASO 7]: Verificar IgnoreRhosts.")
    print("="*100)
    print()

    paso="Paso 7"

    valor=obtener_directiva_ssh("IgnoreRhosts", contenido)

    if valor is None:
        resultado_ok("IgnoreRhosts no configurado (por defecto: yes)")
    elif valor.lower()=="yes":
        resultado_ok("IgnoreRhosts = yes")
    else:
        resultado_fail("IgnoreRhosts = no (ficheros .rhosts son aceptados)", paso)


def verificar_paso8(contenido):
    print()
    print("="*100)
    print("[PASO 8]: Verificar StrictModes.")
    print("="*100)
    print()

    paso="Paso 8"

    valor=obtener_directiva_ssh("StrictModes", contenido)

    if valor is None:
        resultado_ok("StrictModes no configurado (por defecto: yes)")
    elif valor.lower()=="yes":
        resultado_ok("StrictModes = yes")
    else:
        resultado_fail("StrictModes = no (no se verifican permisos de ficheros SSH)", paso)


def verificar_paso9(contenido):
    print()
    print("="*100)
    print("[PASO 9]: Verificar PermitUserEnvironment.")
    print("="*100)
    print()

    paso="Paso 9"

    valor=obtener_directiva_ssh("PermitUserEnvironment", contenido)

    if valor is None:
        resultado_ok("PermitUserEnvironment no configurado (por defecto: no)")
    elif valor.lower()=="no":
        resultado_ok("PermitUserEnvironment = no")
    else:
        resultado_fail("PermitUserEnvironment = yes (los usuarios pueden inyectar variables de entorno)", paso)



def verificar_paso10(contenido):
    print()
    print("="*100)
    print("[PASO 10]: Verificar PrintLastLog.")
    print("="*100)
    print()

    paso="Paso 10"

    valor=obtener_directiva_ssh("PrintLastLog", contenido)

    if valor is None:
        resultado_ok("PrintLastLog no configurado (por defecto: yes)")
    elif valor.lower()=="no":
        resultado_ok("PrintLastLog = yes")
    else:
        resultado_fail("PrintLastLog = no (no se muestra la última conexión al usuario)", paso)




def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    print()
    print("="*100)
    print("[AUDITORÍA MÓDULO 5]: Conexiones SSH.")
    print("="*100)
    print()

    #sshd config existe?
    if not os.path.isfile(SSHD_CONFIG):
        print()
        resultado_fail(f"{SSHD_CONFIG} no encontrado. ¿Está instalado OpenSSH Server?", "General")
        mostrar_resumen("fix_mod5.py")
        volver_al_menu()
        return
    
    contenido=leer_fichero(SSHD_CONFIG, paso="General")
    if contenido is None:
        resultado_fail(f"No se pudo leer {SSHD_CONFIG}", "General")
        mostrar_resumen("fix_mod5.py")
        volver_al_menu()
        return
    

    print()
    print("     Comprobando configuraciones de los pasos 1 al 13...")
    print()

    verificar_paso1(contenido)
    verificar_paso2(contenido)
    verificar_paso3(contenido)
    verificar_paso4(contenido)
    verificar_paso5(contenido)
    verificar_paso6(contenido)
    verificar_paso7(contenido)
    verificar_paso8(contenido)
    verificar_paso9(contenido)
    verificar_paso10(contenido)
    verificar_permisos(SSHD_CONFIG, "600", 0, 0, paso="General")



    mostrar_resumen("fix_mod4.py")

    if contadores["checksFail"]>0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__=="__main__":
    main()





