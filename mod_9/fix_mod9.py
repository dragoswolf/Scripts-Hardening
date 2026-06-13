#!/usr/bin/env python3
#=========================================================================================================
# fix_mod9.py - Script de fortificación para el módulo 9 - Firewall (UFW)
#=========================================================================================================
# Este script implementa las siguientes medidas de seguridad:
#
#   Paso 1: Instalar y activar UFW, configurar política por defecto y permitir SSH
#   Paso 2: Ver reglas activas del firewall
#   Paso 3: Abrir puertos/servicios adicionales
#   Paso 4: Eliminar reglas existentes
#   Paso 5: Activar logging de UFW
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo9_fix.log
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================


import os
import sys
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, 
                   registrar_errores, 
                   comprobar_root, 
                   ejecutar_comando,
                   ejecutar_comando_check, 
                   volver_al_menu, 
                   leer_fichero,
                   print_info,
                   print_aviso,
                   print_correcto,
                   print_error)


#=========================================================================================================
# CONSTANTES
#=========================================================================================================
LOG_FILE="/var/log/hardening/modulo9_fix.log"

SSHD_CONFIG="/etc/ssh/sshd_config"
#=========================================================================================================



#=========================================================================================================
# FUNCIONES AUXILIARES
#=========================================================================================================
def obtener_puerto_ssh():
    """
    Lee el puerto SSH configurado en sshd_config.

    Return:
        str: Número de puerto SSH configurado
    """

    contenido=leer_fichero(SSHD_CONFIG)

    if contenido is None:
        return "22"
    
    for linea in contenido.splitlines():
        limpia=linea.strip()
        if limpia.startswith("Port ") and not limpia.startswith("#"):
            partes=limpia.split()
            if len(partes)>=2 and partes[1].isdigit():
                return partes[1]
            
    return "22"


def ufw_activo():
    """
    Comprueba si UFW está activo.

    Return:
        bool: True si UFW está activo, False en caso contrario
    """

    rc, salida, _=ejecutar_comando_check(["ufw", "status"])
    if rc==0 and "active" in salida.lower():
        for linea in salida.splitlines():
            if "status:" in linea.lower() and "inactive" not in linea.lower():
                return True
    return False
#=========================================================================================================

def paso1_instalar_activa_ufw():
    """
    Verifica si UFW está instalado, de lo contrario lo instala, configura la política
    por defecto, permite SSH y activa el firewall.
    """
    print()
    print("="*100)
    print("[PASO 1]: Verificar/Instalar y activar UFW")
    print("="*100)
    print_info("Verifica si UFW está instalado, de lo contrario lo instala, configura\n" \
    "       la política por defecto, permite SSH y activa el firewall.")
    print()

    paso="Paso 1"

    # 1. Verificar/instalar UFW
    rc, _,_=ejecutar_comando_check(["dpkg", "-s", "ufw"])
    if rc!=0:
        print_info("Instalado UFW...")
        ejecutar_comando(["apt", "install", "-y","ufw"], "instalar UFW", paso, mostrarSalida=True)
        print()
    else:
        print_correcto("UFW ya está instalado.")

    # 2. Configurar política por defecto
    print()

    print_info("Configurando política por defecto...")
    ejecutar_comando(["ufw", "default", "deny", "incoming"], "política deny incoming", paso)
    print_correcto("Política entrante: DENY (denegar todo por defecto)")
    ejecutar_comando(["ufw", "default", "allow", "outgoing"], "política allow outgoing", paso)
    print_correcto("Política saliente: ALLOW (permitir todo por defecto).")
    print()

    # 3. Permitir SSH antes de activar
    puertoSSH=obtener_puerto_ssh()
    
    print_info(f"Puerto SSH detectado: {puertoSSH}")
    print_info(f"Permitiendo SSH (puerto {puertoSSH}) en el firewall...")

    ejecutar_comando(["ufw", "allow", f"{puertoSSH}/tcp"], f"permitir SSH en puerto {puertoSSH}", paso)
    print_correcto(f"SSH (puerto {puertoSSH}) permitido.")
    print()

    # 4. Activar UFW, habilitarlo en el arranque y mostrar el estado

    if ufw_activo():
        print_correcto("UFW ya está activo.")
    else:
        print_info("Activando UFW...")
        ejecutar_comando(["ufw", "--force", "enable"], "activar UFW", paso)
        print_correcto("UFW activado correctamente.")

    ejecutar_comando(["systemctl", "enable", "ufw"], "habilitar UFW en el arranque", paso)

    print()
    print_info("Estado actual del firewall:")
    print()
    rc, salida, _=ejecutar_comando_check(["ufw", "status", "verbose"])

    if rc==0:
        for linea in salida.splitlines():
            print(f"    {linea}")


def paso2_ver_reglas():
    """
    Muestra las reglas activas del firewall.
    """
    print()
    print("="*100)
    print("[PASO 2]: Ver reglas activas del firewall")
    print("="*100)
    print_info("Muestra las reglas activas del firewall")
    print()

    # 2a. Verificar UFW
    if not ufw_activo():
        print_aviso("UFW no está activo. Ejecuta el paso 1 primero.")
        return
    
    # 2b. Mostrar estado detallado de UFW
    rc, salida, _=ejecutar_comando_check(["ufw", "status", "verbose"])
    if rc==0:
        for linea in salida.splitlines():
            print(f"    {linea}")
    else:
        print_error("No se pudo obtener el estado de UFW.")

    # 2c. Mostrar también la versión numerada (útil para el paso 4)
    print()
    print_info("Reglas numeradas (referencia para eliminar):")
    print()
    rc, salida, _=ejecutar_comando_check(["ufw", "status", "numbered"])
    if rc==0:
        for linea in salida.splitlines():
            print(f"    {linea}")


def paso3_abrir_puertos():
    """
    Menú interactivo para abrir puertos/servicios adicionales en UFW.
    Permite especificar puerto o nombre de servicio, y opcionalmente
    restringir por IP de origen.
    """
    print()
    print("="*100)
    print("[PASO 3]: Abrir puertos/servicios adicionales")
    print("="*100)
    print_info("Menú interactivo para abrir puertos/servicios adicionales en UFW.\n" \
    "       Permite especificar puerto o nombre de servicio, y opconalmente restringir por\n" \
    "       IP de origen")
    print()

    paso="Paso 3"

    if not ufw_activo():
        print_aviso("UFW no está activo. Ejecuta el paso 1 primero.")
        return
    
    print_info("Puedes introducir:")
    print(" - Un número de puerto: 80, 443, 3306, etc")
    print(" - Un servicio conocido: http, https, smtp, etc")
    print(" - Puerto con protocolo: 80/tcp, 53/udp, etc")
    print()

    while True:
        entrada=input("Puerto o servicio (dejar vacío para terminar): ").strip()

        if not entrada:
            break

        # Restringir por IP?
        ipOrigen=input("¿Restringir a una IP o subred? (dejar vacío para cualquier origen): ").strip()

        # 3a. Construir comando
        if ipOrigen:
            if not re.match(r'^[\d\./]+$', ipOrigen):
                print_error("Formato de IP no válido.")
                continue
            
            # 3b. Separar puerto y protocolo si viene en formato <puerto>/<protocolo>
            if "/" in entrada:
                puerto, protocolo=entrada.split("/", 1)
                comando=["ufw", "allow", "from", ipOrigen, "to", "any", "port", puerto, "proto", protocolo]
            else:
                comando=["ufw", "allow", "from", ipOrigen, "to", "any", "port", entrada]
                
            descripcion=f"permitir {entrada} desde {ipOrigen}"

        else:
            comando=["ufw", "allow", entrada]
            descripcion=f"permitir {entrada}"

        # 3c. ejecutar comando y ver resultado del mismo.
        rc, salida, stderr=ejecutar_comando_check(comando)

        if rc==0:
            print_correcto(f"Regla añadida: {descripcion}")
        else:
            errorMsg=stderr.strip() if stderr.strip() else salida.strip()
            print_error(f"No se pudo añadir la regla: {errorMsg}")
            registrar_errores(paso, f"No se pudo {descripcion}: {errorMsg}")
        
        print()

    # 3d. Mostrar reglas actualizadas
    print()
    print_info("Reglas activas actualizadas:")
    print()
    rc, salida, _=ejecutar_comando_check(["ufw", "status", "numbered"])

    if rc==0:
        for linea in salida.splitlines():
            print(f"    {linea}")


def paso4_eliminar_reglas():
    """
    Muestra las reglas numeradas y permite eliminar reglas seleccionadas.
    Protege contra la eliminación accidental de la regla de SSH
    """
    print()
    print("="*100)
    print("[PASO 4]: Eliminar reglas existentes")
    print("="*100)
    print_info("Muestra las reglas numeradas y permite eliminar reglas seleccionadas.\n" \
    "       Protege contra la eliminación accidental de la regla de SSH.")
    print()

    paso="Paso 4"

    # 4a. Comprobar UFW
    if not ufw_activo():
        print_aviso("UFW no está activo. Ejecuta el paso 1 primero.")
        return
    
    # 4b. Obtener puerto SSH para protegerlo
    puertoSSH=obtener_puerto_ssh()
    

    while True:
        # 4c. Mostrar reglas numeradas actualizadas
        rc, salida, _=ejecutar_comando_check(["ufw", "status", "numbered"])

        if rc!=0:
            print_error("No se pudieron obtener las reglas.")
            break

        # 4d. Verificar si hay reglas
        reglas=[]
        for linea in salida.splitlines():
            if linea.strip().startswith("["):
                reglas.append(linea.strip())
        
        if not reglas:
            print_info("No hay reglas configuradas.")
            break

        print_info("Reglas activas:")
        for linea in salida.splitlines():
            print(f"    {linea}")
        
        print()
        
        numStr=input("Número de regla a eliminar (dejar vacío para terminar): ").strip()

        if not numStr:
            break

        if not numStr.isdigit():
            print_error("Introduce un número válido.")
            continue

        numRegla=int(numStr)

        # 4d. Verificar que el número es válido
        if numRegla<1 or numRegla>len(reglas):
            print_error(f"Número fuera de rango (1- {len(reglas)}).")
            continue

        # 4e. Proteger puerto SSH
        reglaSeleccionada=reglas[numRegla-1].lower()
        esSSH=(f"{puertoSSH}/tcp" in reglaSeleccionada or f"{puertoSSH}" in reglaSeleccionada)

        if esSSH:
            print()
            print_aviso(f"Esta regla parece ser la regla de SSH (puerto {puertoSSH})")
            print("          Eliminar esta regla puede dejarte sin acceso remoto al servidor.")
            resp=input("          ¿Estás SEGURO de que quieres eliminarla? si/no: ").strip()

            if resp.lower()!="si":
                print_info("Regla NO eliminada")
                continue

        # 4f. Eliminar la regla
        rc, _, stderr=ejecutar_comando_check(["ufw", "--force", "delete", str(numRegla)])

        if rc==0:
            print_correcto(f"Regla {numRegla} eliminada.")
        else:
            print_error(f"No se pudo eliminar: {stderr.strip()}")
            registrar_errores(paso, f"No se pudo eliminar regla {numRegla}: {stderr.strip()}")
        
        print()

def paso5_activar_logging():
    """
    Activa el logging de UFW en nivel low.
    """
    print()
    print("="*100)
    print("[PASO 5]: Activar logging de UFW")
    print("="*100)
    print_info("Activa el logging de UFW en nivel low.")
    print()

    paso="Paso 5"

    if not ufw_activo():
        print_aviso("UFW no está activo. Ejecuta el paso 1 primero.")
        return
    
    # 5a. Verificar estado actual del logging
    rc, salida, _=ejecutar_comando_check(["ufw", "status", "verbose"])
    loggingActivo=False
    
    if rc==0:
        for linea in salida.splitlines():
            if "logging:" in linea.lower():
                print(f"    Estado actual: {linea.strip()}")
                if "on" in linea.lower():
                    loggingActivo=True
                break
    print()

    # 5b. Activar logging
    if loggingActivo:
        print_correcto("El logging de UFW ya está activo.")
    else:
        print_info("Activando logging en nivel low...")
        ejecutar_comando(["ufw", "logging", "low"], "activar logging de UFW", paso)
        print_correcto("Logging activado.")
    
    print()
    print_info("Los paquetes bloqueados se registran en /var/log/ufw.log")


def mostar_menu():
    print()
    print("="*100)
    print("MÓDULO 9: Firewall.")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Verificar/Instalar UFW y permitir SSH.")
    print("     2. Ver reglas activas. [OPCIONAL]")
    print("     3. Abrir puertos/servicios adicionales. [OPCIONAL]")
    print("     4. Eliminar reglas existentes. [OPCIONAL]")
    print("     5. Activar logging.")
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
                paso1_instalar_activa_ufw()
                volver_al_menu()
            case "2":
                paso2_ver_reglas()
                volver_al_menu()
            case "3":
                paso3_abrir_puertos()
                volver_al_menu()
            case "4":
                paso4_eliminar_reglas()
                volver_al_menu()
            case "5":
                paso5_activar_logging()
                volver_al_menu()
            case "q":
                print_info("Saliendo del script.")
                sys.exit(0)
            case _:
                print_error("Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()
    