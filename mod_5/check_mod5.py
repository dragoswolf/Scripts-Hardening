#!/usr/bin/env python3
#=========================================================================================================
# check_mod5.py - Script de verificación para el módulo 5 - SSH (Secure Shell)
#=========================================================================================================
# Este script implementa las siguientes medidas de seguridad:
#
#   Paso 1:     Verificar el puerto SSH
#   Paso 2:     Verificar acceso por usuarios (AllowUsers/DenyUsers)
#   Paso 3:     Verificar autenticación GSSAPI
#   Paso 4:     Verificar LoginGraceTime
#   Paso 5:     Verificar ClientAliveInterval y ClientAliveCountMax
#   Paso 6:     Verificar HostbasedAuthentication
#   Paso 7:     Verificar IgnoreRhosts
#   Paso 8:     Verificar StrictModes
#   Paso 9:     Verificar PermitUserEnvironment
#   Paso 10:    Verificar PrintLastLog
#   Paso 11:    Verificar Banner SSH configurado
#   Paso 12:    Verificar PermitEmptyPasswords
#   Paso 13:    Verificar PermitRootLogin
#   Paso 14:    Verificar LogLevel
#   Paso 15:    Verificar límites de conexión
#   Paso 16:    Verificar algoritmos criptográficos
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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
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

#=========================================================================================================
# CONSTANTES
#=========================================================================================================
SSHD_CONFIG="/etc/ssh/sshd_config"

LOG_FILE="/var/log/hardening/modulo5_check.log"

CIPHERS_INSEGUROS=[
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256"
]

KEX_INSEGUROS = [
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1"
]

MACS_INSEGUROS = [
    "hmac-md5", 
    "hmac-md5-96", 
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com", 
    "hmac-sha1", 
    "hmac-sha1-96",
    "hmac-sha1-etm@openssh.com", 
    "hmac-sha1-96-etm@openssh.com",
    "umac-64@openssh.com", 
    "umac-64-etm@openssh.com"
]

#=========================================================================================================

#Función auxiliar
def obtener_directiva_ssh(directiva, contenido):
    """
    Busca una directiva en el contenido de sshd_config y devuelve su valor.

    Solo busca líneas activas (no comentadas). SI la directiva no se encuentra o está comentada,
    devuelve None.

    Args:
        directiva (str): Nombre de la directiva SSH
        contenido (str): Contenido completo de sshd_config

    Return:
        str o None: Valor de la directiva, o None si no se encuentra.
    """
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

def verificar_algoritmos(tipoAlgo, listaCifrado, contenido, paso):

    valor=obtener_directiva_ssh(tipoAlgo, contenido)
    if valor is None:
        resultado_warn(f"{tipoAlgo} no configurado.")
    else:
        cifrados=[c.strip() for c in valor.split(",")]
        inseguros=[c for c in cifrados if c in listaCifrado]

        if inseguros:
            resultado_fail(f"{tipoAlgo} inseguros detectados: {', '.join(inseguros)}", paso)
        else:
            resultado_ok(f"{tipoAlgo}: {len(cifrados)} algoritmo(s) seguro(s).")


#Medidas de seguridad
def verificar_paso1(contenido):
    """
    Verifica que el puerto SSH no es e estándar (22)

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
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
    """
    Verifica que AllowUsers está configurado para restringir acceso SSH

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
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
    """
    Verifica que la autenticación GSSAPI está habilitada

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
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
    """
    Verifica que LoginGraceTime tiene un valor bajo (<= 60 segundos)

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
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
    """
    Verifica que los timeouts de sesión SSH están configurados.

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
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
    """
    Verifica que HostbasedAuthentication está deshabilitado

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
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
    """
    Verifica que IgnoreRhosts está habilitado

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
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
    """
    Verifica que StrictModes está habilitado.

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
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
    """
    Verifica que PermitUserEnvironment está deshabilitado

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
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
    """
    Verifica que PrintLastLog está habilitado

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
    print()
    print("="*100)
    print("[PASO 10]: Verificar PrintLastLog.")
    print("="*100)
    print()

    paso="Paso 10"

    valor=obtener_directiva_ssh("PrintLastLog", contenido)

    if valor is None:
        resultado_ok("PrintLastLog no configurado (por defecto: yes)")
    elif valor.lower()=="yes":
        resultado_ok("PrintLastLog = yes")
    else:
        resultado_fail(f"PrintLastLog = {valor.lower()} (no se muestra la última conexión al usuario)", paso)


def verificar_paso11(contenido):
    """
    Verifica que la directiva Banner apunta a /etc/issue.net
    y que el fichero existe.

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
    print()
    print("="*100)
    print("[PASO 11]: Verificar Banner SSH.")
    print("="*100)
    print()

    paso="Paso 11"


    if not os.path.isfile("/etc/issue.net"):
        resultado_fail("/etc/issue.net no existe. Ejecuta el módulo 2, paso 2 para crearlo.", paso)
        return
    
    valor=obtener_directiva_ssh("Banner", contenido)

    if valor is None:
        resultado_fail("La directiva 'Banner' no está configurada en sshd_config.", paso)
    elif valor=="/etc/issue.net":
        resultado_ok("Banner = /etc/issue.net")
    else:
        resultado_warn(f"Banner = {valor} (esperado /etc/issue.net)")


def verificar_paso12(contenido):
    """
    Verifica que PermitEmptypasswords está deshabilitado.

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
    print()
    print("="*100)
    print("[PASO 12]: Verificar PermitEmptyPasswords.")
    print("="*100)
    print()

    paso="Paso 12"

    valor=obtener_directiva_ssh("PermitEmptyPasswords", contenido)

    if valor is None:
        #Por defecto es "no"
        resultado_ok("PermitEmptyPasswords no configurado (por defecto es no).")
    elif valor.lower()=="no":
        resultado_ok("PermitEmptyPasswords = no")
    else:
        resultado_fail("PermitEmptyPasswords no es 'no'.\n" \
        "       Es posible que se permitan contraseñas vacías por SSH", paso)


def verificar_paso12(contenido):
    """
    Verifica que PermitRootLogin está deshabilitado

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
    print()
    print("="*100)
    print("[PASO 13]: Verificar PermitRootLogin.")
    print("="*100)
    print()

    paso="Paso 13"

    valor=obtener_directiva_ssh("PermitRootLogin", contenido)

    if valor is None:
        resultado_warn("PermitRootLogin no configurado explícitamente.")
    elif valor.lower() == "no":
        resultado_ok("PermitRootLogin = no")
    elif valor.lower()== "prohibit-password":
        resultado_warn("PermitRootLogin = prohibit password (recomendado 'no')")
    else:
        resultado_fail(f"PermitRootLogin = {valor} (acceso root por SSH permitido)", paso)


def verificar_paso14(contenido):
    """
    Verifica que LogLevel está configurado a INFO o superior

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
    print()
    print("="*100)
    print("[PASO 14]: Verificar LogLevel.")
    print("="*100)
    print()

    paso="Paso 14"

    valor=obtener_directiva_ssh("LogLevel", contenido)

    nivelesAceptables=["INFO", "VERBOSE"]

    if valor is None:
        resultado_ok("LogLevel no configurado (por defecto: INFO)")
    elif valor.upper() in nivelesAceptables:
        resultado_ok(f"LogLevel = {valor}")
    else:
        resultado_fail(f"LogLevel = {valor} (esperado INFO o VERBOSE)", paso)


def verificar_paso15(contenido):
    """
    Verifica límites de conexión

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
    print()
    print("="*100)
    print("[PASO 15]: Verificar límites de conexión.")
    print("="*100)
    print()

    paso="Paso 15"

    listaAlgos={
        "Cipher": CIPHERS_INSEGUROS,
        "KexAlgorithm": KEX_INSEGUROS,
        "MACs": MACS_INSEGUROS
    }

    for algo, lista in listaAlgos:
        verificar_algoritmos(algo, lista, contenido, paso)


def verificar_paso16(contenido):
    """
    Verifica límites de conexión

    Args:
        contenido (str):    Contenido del fichero de configuración de SSH
    """
    print()
    print("="*100)
    print("[PASO 15]: Verificar límites de conexión.")
    print("="*100)
    print()

    paso="Paso 16"


    # 16a Ciphers
    valor=obtener_directiva_ssh("Ciphers", contenido)
    if valor is None:
        resultado_warn("Ciphers no configurado.")
    else:
        cifrados=[c.strip() for c in valor.split(",")]
        inseguros=[c for c in cifrados if c in CIPHERS_INSEGUROS]

        if inseguros:
            resultado_fail(f"Ciphers inseguros detectados: {', '.join(inseguros)}", paso)
        else:
            resultado_ok(f"Ciphers: {len(cifrados)} algoritmo(s) seguro(s).")

    # 16b. KexAlgorithms
    valor=obtener_directiva_ssh("KexAlgorithms", contenido)
    if valor is None:
        resultado_warn("KexAlgorithms no configurado.")
    else:
        kex=[k.strip() for k in valor.split(",")]
        inseguros=[k for k in kex if k in KEX_INSEGUROS]

        if inseguros:
            resultado_fail(f"KexAlgorithms inseguros detectados: {', '.join(inseguros)}", paso)
        else:
            resultado_ok(f"KexAlgorithms: {len(cifrados)} algoritmo(s) seguro(s).")


    # 16c MACs
    valor=obtener_directiva_ssh("MACs", contenido)
    if valor is None:
        resultado_warn("MACs no configurado.")
    else:
        macs=[m.strip() for m in valor.split(",")]
        inseguros=[m for m in macs if m in MACS_INSEGUROS]

        if inseguros:
            resultado_fail(f"MACs inseguros detectados: {', '.join(inseguros)}", paso)
        else:
            resultado_ok(f"MACs: {len(cifrados)} algoritmo(s) seguro(s).")





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
        mostrar_resumen("check_mod5.py")
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
    verificar_paso11(contenido)
    verificar_permisos(SSHD_CONFIG, "600", 0, 0, paso="General")



    mostrar_resumen("fix_mod5.py")

    if contadores["checksFail"]>0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__=="__main__":
    main()





