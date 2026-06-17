#!/usr/bin/env python3
#=========================================================================================================
# fix_mod13.py - Script de fortificación para el módulo 12 - Fail2Ban
#=========================================================================================================
# Este script implementa las siguientes medidas de seguridad:
#
#   Paso 1: Instalar Fail2Ban
#   Paso 2: Configurar whitelist de IPs
#   Paso 3: Crear jail.local con protección SSH y parámetros de baneo
#   Paso 4: Habilitar y arrancar el servicio
#   Paso 5: Verificar estado del jail SSH
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo13_fix.log
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
                   ejecutar_comando,
                   ejecutar_comando_check,
                   escribir_fichero,
                   leer_fichero,
                   volver_al_menu,
                   print_aviso,
                   print_correcto,
                   print_error,
                   print_info,
                   obtener_puerto_ssh,
                   ufw_activo)


#=========================================================================================================
# CONSTANTES
#=========================================================================================================
LOG_FILE="/var/log/hardening/modulo13_fix.log"
JAIL_LOCAL="/etc/fail2ban/jail.local"
#=========================================================================================================
# FUNCIONES AUXILIARES
#=========================================================================================================
def validar_ip(ip):
    """
    Valida que una cadena sea una IP válida o una subred CIDR.
    
    Args:
        ip (str): Dirección IP o subred (ej: "192.168.1.10", "10.0.0.0/24")
    
    Return:
        bool: True si el formato es válido, False en caso contrario
    """

    #Patrón para IP con subred opcional
    patron=r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    if not re.match(patron, ip):
        return False
    
    # Verificar que los octetos estén entre 0 y 255
    partes=ip.split("/")[0].split(".")
    for octeto in partes:
        if int(octeto) > 255:
            return False
        
    # Verificar que la máscara CIDR es válida (0-32)
    if "/" in ip:
        mascara=int(ip.split("/")[1])
        if mascara>32:
            return False
        
    return True
#=========================================================================================================
# MEDIDAS DE SEGURIDAD
#=========================================================================================================
def paso1_instalar_f2b():
    """
    Instala el paquete fail2ban si no está presente.
    """
    print()
    print("="*100)
    print("[PASO 1]: Instalar Fail2Ban.")
    print("="*100)
    print_info("Instala el servicio Fail2Ban si no está presente.")
    print()

    paso="Paso 1"

    # 1a. Verificar dependencia UFW
    if not ufw_activo():
        print_aviso("UFW no está activo. Fail2Ban lo necesita para su correcto funcionamiento.")
        print_aviso("Se recomienda ejecutar primero el módulo 9 (Firewall UFW).")

        resp=input("¿Continuar de todas formas? (s/n): ").strip().lower()

        if resp!="s":
            print_info("Instalación cancelada.")
            return
        print()

    # 1b. Verificar si Fail2Ban ya está instalado
    rc, _, _=ejecutar_comando_check(["dpkg", "-s", "fail2ban"])
    if rc==0:
        print_correcto("Fail2Ban ya está instalado")
    else:
        print_info("Instalando Fail2Ban...")
        if not ejecutar_comando(["apt-get", "install", "-y", "fail2ban"], "instalar Fail2Ban", paso, mostrarSalida=True):
            print_error("Error al instalar Fail2Ban.")
        else:
            print_correcto("Fail2ban instalado correctamente.")


def paso2_configurar_whitelist():
    """
    Solicita al usuario las IPs que deben incluirse en la whitelist.
    Devuelve la lista de IPs para usarla en la configuración del jail.

    Return:
        list: Lista de IPs/subredes a incluir en ignoreip
    """
    print()
    print("="*100)
    print("[PASO 2]: Configurar whitelist de IPs.")
    print("="*100)
    print_info("Define las IPs que Fail2Ban nunca bloqueará. Esto evita bloqueos accidentales\n"
    "       de administradores o usuarios legítimos.")
    print()
    paso="Paso 2"

    # Localhost por defecto permitido.
    ipsWhitelist=["127.0.0.1/8", "::1"]
    
    print_info("IPs incluidas por defecto:")
    print_info("        - 127.0.0.1/8 (localhost IPv4)")
    print_info("        - ::1 (localhost IPv6)")
    print()
    print_info("Introduce las IPs o subredes adicionales que deseas añadir a la whitelist.\n\
            (Ejemplo: 192.168.1.0/24, 10.0.0.5)")
    print()

    # 2a. Añadir IPs a la whitelist
    while True:
        ip=input("IP o subred: ").strip()

        if not ip:
            break

        if validar_ip(ip):
            if ip not in ipsWhitelist:
                ipsWhitelist.append(ip)
                print_correcto(f"{ip} añadida a la whitelist.")
            else:
                print_info(f"{ip} ya está en la whitelist.")
        else:
            print_error(f"Formato no válido: {ip}. Ejemplos válidos: 192.168.1.0/24, 10.0.0.5")
        print()

    # 2b. Mostrar resumen
    print_info("Whitelist final:")
    for ip in ipsWhitelist:
        print(f"    - {ip}")

    return ipsWhitelist


def paso3_crear_jail(ipsWhitelist):
    """
    Crea el fichero /etc/fail2ban/jail.local con la configuración de protección SSH.

    Parámetros:
        ipsWhitelist (list): Lista de IPs para ignoreip
    """
    print()
    print("="*100)
    print("[PASO 3]: Configurar Fail2Ban.")
    print("="*100)
    print_info("Crea /etc/fail2ban/jail.local con protección SSH, umbrales de baneo\n" \
    "       y whitelist configurada.")
    print()
    paso="Paso 3"

    # 3a. Obtener variables necesarias
    puertoSSH=obtener_puerto_ssh()
    ignoreIpStr = " ".join(ipsWhitelist)

    contenido = f"""
#=========================================================================================================
# jail.local — Configuración personalizada de Fail2Ban
#=========================================================================================================
# Generado automáticamente por el script de hardening.
# Este fichero prevalece sobre jail.conf y no se sobrescribe
# con las actualizaciones del paquete.
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================

[DEFAULT]

# --- Whitelist ---
# IPs que nunca serán baneadas (administradores, red interna)
ignoreip = {ignoreIpStr}

# --- Parámetros de baneo ---
# bantime:  duración del baneo en segundos (1800 = 30 minutos)
# findtime: ventana de tiempo para contar intentos (600 = 10 minutos)
# maxretry: intentos fallidos permitidos antes de banear
bantime  = 1800
findtime = 600
maxretry = 5

# --- Backend de baneo ---
# Utilizar UFW para gestionar las reglas de baneo
banaction = ufw

#=========================================================================================================
# JAIL: SSH
#=========================================================================================================
# Monitoriza /var/log/auth.log en busca de intentos fallidos de
# autenticación SSH y banea las IPs atacantes.
#=========================================================================================================

[sshd]
enabled  = true
port     = {puertoSSH}
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
"""

    # 3b. Escribir el fichero
    if escribir_fichero(JAIL_LOCAL, contenido, permisos=0o644, paso=paso):
        print_correcto(f"{JAIL_LOCAL} creado correctamente.")
        print()
        print_info("Configuración aplicada:")
        print_info(f"   - Whitelist: {ignoreIpStr}")
        print_info("    - Baneo: 30 minutos tras 5 intentos en 10 minutos.")
        print_info(f"   - Puerto SSH protegido: {puertoSSH}.")
        print_info("    - Backend de baneo: UFW.")
    else:
        print_error(f"No se pudo crear {JAIL_LOCAL}.")


def paso4_habilitar_servicio():
    """
    Habilita y arranca (o reinicia) el servicio fail2ban.
    """
    print()
    print("="*100)
    print("[PASO 4]: Habilitar y arrancar Fail2Ban.")
    print("="*100)
    print_info("Habilita Fail2Ban en el arranque del sistema e inicia (o reinicia) el servicio\n" \
    "       para aplicar la configuración.")
    print()
    paso="Paso 4"

    # 4a. Verificar que fail2ban está instalado
    rc,_,_=ejecutar_comando_check(["dpkg", "-s", "fail2ban"])
    if rc!=0:
        print_error("Fail2Ban no está instalado. Ejecute el paso 1.")
        return
    
    # 4b. Habilitar fail2ban en el arranque
    if ejecutar_comando(["systemctl", "enable", "fail2ban"], "habilitar fail2ban en el arranque", paso):
        print_correcto("Fail2Ban habilitado en el arranque.")
    else:
        print_error("No se pudo habilitar Fail2Ban en el arranque.")

    
    # 4c. Comprobar si ya está activo
    rc, salida, _=ejecutar_comando_check(["systemctl", "is-active", "fail2ban"])

    # Si está activo, reiniciarlo para aplicar los cambios
    if rc==0 and "active" in salida.strip():
        print_info("Reiniciando Fail2Ban para aplicar la configuración...")
        if ejecutar_comando(["systemctl", "restart", "fail2ban"], "reiniciar Fail2Ban", paso):
            print_correcto("Fail2Ban reiniciado correctamente.")
        else:
            print_error("Fail2Ban no pudo ser reiniciado.")
    else:
        # Si no está activo, arrancarlo
        print_info("Arrancando Fail2Ban...")
        if ejecutar_comando(["systemctl", "start", "fail2ban"], "arrancar Fail2Ban", paso):
            print_correcto("Servicio Fail2Ban arrancado con éxito.")
        else:
            print_error("Servicio Fail2Ban no pudo ser arrancado.", paso)


def paso5_gestionar_whitelist():
    """
    Menú interactivo para ver, añadir y quitar IPs de la whitelist.
    """
    print()
    print("="*100)
    print("[PASO 5]: Gestionar whitelist de IPs.")
    print("="*100)
    print_info("Permite añadir o quitar IPs de la whitelist sin reconfigurar todo el servicio.")
    print()
    paso="Paso 5"

    # 5a. Verificar que jail.local existe
    contenido=leer_fichero(JAIL_LOCAL)
    if contenido is None:
        print_error("No existe jail.local. Ejecuta los paso 1-4 primero.")
        return
    
    # 5b. Extraer la whitelist actual
    ipsActuales=[]
    lineaIgnoreip=None
    for linea in contenido.splitlines():
        limpia=linea.strip()
        if limpia.startswith("ignoreip"):
            lineaIgnoreip = limpia
            ipsActuales= limpia.split("=", 1)[1].strip().split()
            break

    if lineaIgnoreip is None:
        print_error("No se encontró ignoreip en jail.local.")
        return
    
    modificado=False

    # 5c. Hacer las modificaciones
    while True:
        # Mostrar IPs actuales
        print()
        print_info("Whitelist actual:")
        for i, ip in enumerate(ipsActuales, 1):
            print(f"    {i}. {ip}")

        print()
        print_info("  1) Añadir una IP")
        print_info("  2) Eliminar una IP")
        print_info("  q) Terminar")

        opcion=input("Selecciona una opción: ").strip().lower()
        print()

        # Acciones a seleccionar
        #Añadir IP
        if opcion=="a":
            ip=input("IP o subred a añadir: ").strip().lower()
            if not ip:
                continue
            if validar_ip(ip):
                if ip not in ipsActuales:
                    ipsActuales.append(ip)
                    cambios=True
                    print_correcto(f"{ip} añadida.")
                else:
                    print_info(f"{ip} ya está en la whitelist.")
            else:
                print_error(f"Formato no válido: {ip}.")
                print_info("Ejemplos: 192.168.1.10 o 10.0.0.0/24.")
        # Eliminar IP
        elif opcion=="e":
            ip=input("Número de la IP a eliminar: ").strip()
            if not ip.isdigit():
                print_error("Introduce un número válido.")
                continue
            indice=int(ip) -1
            if indice <0 or indice>=len(ipsActuales):
                print_error(f"Número fuera de rango (1-{len(ipsActuales)}).")
                continue

            ipEliminada=ipsActuales[indice]

            # Proteger localhost
            if ipEliminada in ("127.0.0.1/8", "127.0.0.1", "::1"):
                print_aviso(f"{ipEliminada} es localhost. Eliminarlo podría causar problemas.")
                resp=input("¿Está seguro de su eliminación?: ").strip().lower()
                if resp!="s":
                    print_info("IP localhost no eliminada.")
                    continue
                    
            ipsActuales.pop(indice)
            cambios=True
            print(f"{ipEliminada} eliminada.")

        elif opcion=="0":
            break
        else:
            print_error("Opción no valida.")

    print()

    # Aplicar cambios si los hubo
    if cambios:
        nuevoIgnoreip="ignoreip = "+" ".join(ipsActuales)
        contenidoNuevo=contenido.replace(lineaIgnoreip, nuevoIgnoreip)

        if escribir_fichero(JAIL_LOCAL, contenidoNuevo, permisos=0o644, paso=paso):
            print_correcto("Whitelist actualizada en jail.local.")

            # Reiniciar fail2ban para aplicar cambios
            rc, salida, _=ejecutar_comando_check(["systemctl", "is-active", "fail2ban"])
            if rc==0 and "active" in salida.strip():
                print_info("Reiniciando Fail2Ban para aplicar cambios...")
                if ejecutar_comando(["systemctl", "restart", "fail2ban"], "reiniciar Fail2Ban", paso):
                    print_correcto("Fail2Ban reiniciado. Cambios aplicados.")
        else:
            print_error("No se pudo actualizar jail.local.")
    else:
        print_info("Sin cambios.")


def mostrar_menu():
    print()
    print("="*100)
    print("MÓDULO 13: Fail2Ban.")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Instalar Fail2Ban.")
    print("     2. Configurar whitelist de IPs inicial.")
    print("     3. Crear configuración.")
    print("     4. Habilitar y arrancar el servicio.")
    print("     5. Gestionar whitelist.")
    print()
    print("     q. Salir")
    print()
        

def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    while True:
        mostrar_menu()
        opcion=input("Selecciona una opción: ").strip().lower()

        match opcion:
            case "1":
                paso1_instalar_f2b()
                volver_al_menu()
            case "2":
                ipsWhitelist=paso2_configurar_whitelist()
                volver_al_menu()
            case "3":
                if ipsWhitelist is None:
                    print()
                    print_info("Primero hay que configurar la whitelist.")
                    ipsWhitelist=paso2_configurar_whitelist()
                paso3_crear_jail(ipsWhitelist)
                volver_al_menu()
            case "4":
                paso4_habilitar_servicio()
                volver_al_menu()
            case "5":
                paso5_gestionar_whitelist()
                volver_al_menu()
            case "q":
                print()
                print_info("Saliendo del script...")
                sys.exit(0)
            case _:
                print_error("Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()




                
    

