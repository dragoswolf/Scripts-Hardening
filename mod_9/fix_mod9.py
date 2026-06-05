#!/usr/bin/env python3


import os
import sys
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, registrar_errores, comprobar_root, ejecutar_comando,
                   ejecutar_comando_check, volver_al_menu, leer_fichero)


LOG_FILE="/var/log/hardening/modulo9_fix.log"

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


def paso1_instalar_activa_ufw():
    """
    Verifica si UFW está instalado, de lo contrario lo instala, configura la política
    por defecto, permite SSH y activa el firewall.
    """

    print()
    print("="*100)
    print("[PASO 1]: Verificar/Instalar y activar UFW")
    print("="*100)
    print()

    paso="Paso 1"

    # 1. Verificar/instalar UFW
    rc, _,_=ejecutar_comando_check(["dpkg", "-s", "ufw"])
    if rc!=0:
        print(["[INFO]: Instalado UFW..."])
        ejecutar_comando(["apt", "install", "-y","ufw"], "instalar UFW", paso, mostrarSalida=True)
        print()
    else:
        print("[CORRECTO]: UFW ya está instalado.")

    # 2. Configurar política por defecto
    print()

    print("[INFO]: Configurando política por defecto...")
    ejecutar_comando(["ufw", "default", "deny", "incoming"], "política deny incoming", paso)
    print("[CORRECTO]: Política entrante: DENY (denegar todo por defecto)")
    ejecutar_comando(["ufw", "default", "allow", "outgoing"], "política allow outgoing", paso)
    print("[CORRECTO]: Política saliente: ALLOW (permitir todo por defecto).")
    print()

    # 3. Permitir SSH antes de activar
    puertoSSH=obtener_puerto_ssh()
    
    print(f"[INFO]: Puerto SSH detectado: {puertoSSH}")
    print(f"[INFO]: Permitiendo SSH (puerto {puertoSSH}) en el firewall...")

    ejecutar_comando(["ufw", "allow", f"{puertoSSH}/tcp"], f"permitir SSH en puerto {puertoSSH}", paso)
    print(f"[CORRECTO]: SSH (puerto {puertoSSH}) permitido.")
    print()

    # 4. Activar UFW, habilitarlo en el arranque y mostrar el estado

    if ufw_activo():
        print("[CORRECTO]: UFW ya está activo.")
    else:
        print("[INFO]: Activando UFW...")
        ejecutar_comando(["ufw", "--force", "enable"], "activar UFW", paso)
        print("[CORRECTO]: UFW activado correctamente.")

    ejecutar_comando(["systemctl", "enable", "ufw"], "habilitar UFW en el arranque", paso)

    print()
    print("[INFO]: Estado actual del firewall:")
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
    print()

    if not ufw_activo():
        print("[AVISO]: UFW no está activo. Ejecuta el paso 1 primero.")
        return
    
    rc, salida, _=ejecutar_comando_check(["ufw", "status", "verbose"])

    if rc==0:
        for linea in salida.splitlines():
            print(f"    {linea}")
    else:
        print("[ERROR]: No se pudo obtener el estado de UFW.")

    print()
    print("[INFO]: Reglas numeradas (referencia para eliminar):")
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
    print()

    paso="Paso 3"

    if not ufw_activo():
        print("[AVISO]: UFW no está activo. Ejecuta el paso 1 primero.")
        return
    
    print("[INFO]: Puedes introducir:")
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

        if ipOrigen:
            if not re.match(r'^[\d\./]+$', ipOrigen):
                print("[ERROR]: Formato de IP no válido.")
                continue

            comando=["ufw", "allow", "from", ipOrigen, "to", "any", "port", entrada]
            descripcion=f"permitir {entrada} desde {ipOrigen}"
        else:
            comando=["ufw", "allow", entrada]
            descripcion=f"permitir {entrada}"

        rc, salida, stderr=ejecutar_comando_check(comando)

        if rc==0:
            print(f"[CORRECTO]: Regla añadida: {descripcion}")
        else:
            errorMsg=stderr.strip() if stderr.strip() else salida.strip()
            print(f"[ERROR]: No se pudo añadir la regla: {errorMsg}")
            registrar_errores(paso, f"No se pudo {descripcion}: {errorMsg}")
        
        print()

    #Mostrar reglas actualizadas
    print()
    print("[INFO]: Reglas activas actualizadas:")
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
    print()

    paso="Paso 4"

    if not ufw_activo():
        print("[AVISO]: UFW no está activo. Ejecuta el paso 1 primero.")
        return
    
    puertoSSH=obtener_puerto_ssh()
    
    while True:
        rc, salida, _=ejecutar_comando_check(["ufw", "status", "numbered"])

        if rc!=0:
            print("[ERROR]: No se pudieron obtener las reglas.")
            break

        reglas=[]

        for linea in salida.splitlines():
            if linea.strip().startswith("["):
                reglas.append(linea.strip())
        
        if not reglas:
            print("[INFO]: No hay reglas configuradas.")
            break

        print("[INFO]: Reglas activas:")
        for linea in salida.splitlines():
            print(f"    {linea}")
        
        print()
        
        numStr=input("Número de regla a eliminar (dejar vacío para terminar): ").strip()

        if not numStr:
            break

        if not numStr.isdigit():
            print("[ERROR]: Introduce un número válido.")
            continue

        numRegla=int(numStr)

        if numRegla<1 or numRegla>len(reglas):
            print(f"[ERROR]: Número fuera de rango (1- {len(reglas)}).")
            continue

        #Proteger puerto SSH
        reglaSeleccionada=reglas[numRegla-1].lower()
        esSSH=(f"{puertoSSH}/tcp" in reglaSeleccionada or f"{puertoSSH}" in reglaSeleccionada)

        if esSSH:
            print()
            print(f"[AVISO]: Esta regla parece ser la regla de SSH (puerto {puertoSSH})")
            print("          Eliminar esta regla puede dejarte sin acceso remoto al servidor.")
            resp=input("          ¿Estás SEGURO de que quieres eliminarla? si/no: ").strip()

            if resp.lower()!="si":
                print("[INFO]: Regla NO eliminada")
                continue

        rc, _, stderr=ejecutar_comando_check(["ufw", "--force", "delete", str(numRegla)])

        if rc==0:
            print(f"[CORRECTO]: Regla {numRegla} eliminada.")
        else:
            print(f"[ERROR]: No se pudo eliminar: {stderr.strip()}")
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
    print()

    paso="Paso 5"

    if not ufw_activo():
        print("[AVISO]: UFW no está activo. Ejecuta el paso 1 primero.")
        return
    
    # Verificar estado actual del logging
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

    if loggingActivo:
        print("[CORRECTO]: El logging de UFW ya está activo.")
    else:
        print("[INFO]: Activando logging en nivel low...")
        ejecutar_comando(["ufw", "logging", "low"], "activar logging de UFW", paso)
        print("[CORRECTO]: Logging activado.")
    
    print()
    print("[INFO]: Los paquetes bloqueados se registran en /var/log/ufw.log")


def mostar_menu():
    print()
    print("="*100)
    print("Hardening: Firewall.")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Verificar/Instalar UFW y permitir SSH.")
    print("     2. Ver reglas activas")
    print("     3. Abrir puertos/servicios adicionales.")
    print("     4. Eliminar reglas existentes.")
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
                print("\n[INFO]: Saliendo del script.")
                sys.exit(0)
            case _:
                print("[ERROR]: Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()
    