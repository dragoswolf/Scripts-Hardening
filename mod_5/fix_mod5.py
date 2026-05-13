#!/usr/bin/env python3

import os
import sys
import re

sys.path.inser(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, registrar_errores, comprobar_root,
                   ejecutar_comando, ejecutar_comando_check, volver_al_menu,
                   escribir_fichero, leer_fichero, cambiar_permisos)

SSHD_CONFIG="/etc/ssh/sshd_config"
PASSWD="/etc/passwd"
ISSUE_NET="/etc/issue.net"


LOG_FILE="/var/log/hardening/modulo5_fix.log"

BANNER_SSH="""
*********************************************************
*                AVISO - SISTEMA PROTEGIDO              *
*********************************************************
*                                                       *
* El acceso a este sistema está restringido a usuarios  *
* autorizados. Todas las actividades son monitorizadas  *
* y registradas.                                        *
*                                                       *
* El acceso no autorizado está prohibido y será         *
* procesado conforme a la legislación vigente.          *
*                                                       *
* Si no está autorizado, desconéctese inmediatamente.   *
*                                                       *
*********************************************************
"""


# Funciones auxiliares

def configurar_directiva_ssh(directiva, valor, paso="General"):
    contenido=leer_fichero(SSHD_CONFIG, paso=paso)
    if contenido is None:
        registrar_errores(paso, f"No se pudo leer {SSHD_CONFIG}")
        return False
    
    lineas=contenido.splitlines()
    encontrado=False
    modificado=False

    for i, linea in enumerate(lineas):
        limpia=linea.strip()

        if directiva in limpia and not limpia.startswith("#"):
            partes=limpia.split(directiva)
            valorActual=partes[1]

            if limpia.startswith("#") or valorActual==valor:
                lineas[i]=f"{directiva}={valor}"
                print(f"[INFO]: {directiva}: {valorActual} -> {valor}")
                modificado=True
            else:
                print(f"[CORRECTO]: {directiva} ya tiene el valor correcto ({valor})")
            encontrado=True
            break

    if not encontrado:
        lineas.append(f"{directiva}{valor}")
        print(f"[INFO]: {directiva} {valor} añadido al final.")
        modificado=True

    if modificado:
        nuevoContenido="\n".join(lineas)

        if not nuevoContenido.endswith("\n"):
            nuevoContenido+="\n"

        return escribir_fichero(SSHD_CONFIG, nuevoContenido, permisos=0o600, paso=paso)
    
    return True

def recargar_ssh(paso="General"):
    rc,_,stderr=ejecutar_comando_check(["sshd", "-t"])

    if rc!=0:
        registrar_errores(paso, f"Configuración SSH inválida: {stderr.strip()}")
        print(f"[ERROR]: La configuración de SSH no es válida:")
        print(f"         {stderr.strip()}")
        print("[ERROR]: No se ha recargado el servicio.")
        print("[INFO]: Revisa /etc/ssh/sshd_config y corrige el error.")
        return False
    
    ejecutar_comando(["systemctl", "reload", "ssh"], "recargar servicio SSH", paso)

    print("[CORRECTO]: Servicio SSH recargado correctamente.")
    return True



# Medidas de seguridad
def paso1_cambiar_puertos():
    print()
    print("="*100)
    print("[PASO 1]: Cambiar el puerto SSH.")
    print("="*100)
    print()

    paso="Paso 1"

    contenido=leer_fichero(SSHD_CONFIG, paso=paso)
    if contenido is None:
        registrar_errores(paso, f"No se pudo leer {SSHD_CONFIG}.")
        return
    
    puertoActual="22"
    lineas=contenido.splitlines()
    for linea in lineas:
        limpia=linea.strip()
        if limpia.startswith("Port ") and not limpia.startswith("#"):
            puertoActual=limpia.split()[1]
            break

    print(f"[INFO]: Puerto actual: {puertoActual}")
    print()
    print("[INFO]: Recomendaciones:")
    print("        - Usar un puerto entre 1024 y 65535")
    print("        - Evitar puertos conocidos (80, 443, 8080, 3306...)")
    print("        - Ejemplo: 2222, 2022, 49152")
    print()

    nuevoPuerto=input("Introduce el nuevo puerto SSH (o Enter para mantener el actual): ").strip()

    if not nuevoPuerto:
        print("[INFO]: No se realizaron cambios.")
        return
    
    try:
        puerto=int(nuevoPuerto)
    except ValueError:
        print("[ERROR]: El puerto debe ser un número.")
        return
    
    if puerto < 1024 or puerto >65535:
        print("[ERROR]: El puerto debe estar entre 1024 y 65535.")
        return
    
    if puerto==int(puertoActual):
        print(f"[CORRECTO]: El puerto ya es {puerto}.")
        return
    
    rc, salida, _=ejecutar_comando_check(["ss", "-tlnp", f"sport=:{puerto}"])

    if salida.strip().count("\n")>0:
        print(f"[AVISO]: El puerto {puerto} parece estar en uso:")
        print(f"         {salida.strip()}")
        respuesta=input("¿Continuar de todas formas? (s/n): ").strip().lower()
        if respuesta!="s":
            print("[INFO]: No se realizaron cambios.")
            return
        
    if configurar_directiva_ssh("Port", str(puerto), paso):
        recargar_ssh(paso)
        print()
        print(f"[IMPORTANTE]: Recuerda conectarte con: ssh -p {puerto} usuario@servidor")
        print(f"[IMPORTANTE]: Actualiza las reglas del firewall si es necesario.")


def paso2_allow_users():
    print()
    print("="*100)
    print("[PASO 2]: Restringir acceso por usuarios.")
    print("="*100)
    print()

    paso="Paso 2"

    contenido=leer_fichero(SSHD_CONFIG, paso=paso)
    if contenido is None:
        registrar_errores(paso, f"No se pudo leer {SSHD_CONFIG}.")
        return
    
    allowActual=None
    lineas=contenido.splitlines()

    for linea in lineas:
        limpia=linea.strip()
        if limpia.startswith("AllowUsers ") and not limpia.startswith("#"):
            allowActual=limpia.split()[1]
            break

    if allowActual:
        print(f"[INFO]: AllowUsers actual: {allowActual}")
    else:
        print("[INFO]: AllowUsers no está configurado (todos los usuarios pueden conectarse).")

    contenidoPasswd=leer_fichero(PASSWD, paso)
    if contenidoPasswd:
        usuariosHumanos=[]
        lineas=contenidoPasswd.splitlines()
        for linea in lineas:
            campos=linea.split(":")
            uid=campos[1]
            
            if 1000<=uid<65535:
                usuariosHumanos.append(campos[0])
        if usuariosHumanos:
            print(f"\n[INFO]: Usuarios humanos del sistema: {', '.join(usuariosHumanos)}")

    print()
    print("[AVISO]: Si no incluyes tu usuario, perderás acceso SSH.")
    print()

    usuarios=input("Usuarios permitidos (o Enter para no cambiar): ").strip()

    if not usuarios:
        print("[INFO]: No se realizaron cambios.")
        return
    
    listaUsuarios=usuarios.split()

    for usuario in listaUsuarios:
        rc,_,_=ejecutar_comando_check(["id", usuario])
        if rc !=0:
            print(f"[AVISO]: El usuario '{usuario}' no existe en el sistema.")
            respuesta=input("¿Continuar de todas formas? (s/n): ").strip().lower()
            if respuesta!="s":
                print("[INFO]: No se realizaron cambios.")

    if configurar_directiva_ssh("AllowUsers", "\n".join(usuarios), paso):
        recargar_ssh(paso)

def paso3_deshabilitar_gssapi():
    print()
    print("="*100)
    print("[PASO 3]: Deshabilitar autenticacoón GSSAPI.")
    print("="*100)
    print()

    paso="Paso 3"

    if configurar_directiva_ssh("GSSAPIAuthentication", "no", paso):
        recargar_ssh(paso)

    
def paso4_login_grace_time():
    print()
    print("="*100)
    print("[PASO 4]: Configurar LoginGraceTime.")
    print("="*100)
    print()

    paso="Paso 4"

    print("[INFO]: LoginGraceTime limita el tiempo para autenticarse.")
    print("[INFO]: Valor recomendado: 30 segundos.")
    print()

    if configurar_directiva_ssh("LoginGraceTime", "30", paso):
        recargar_ssh(paso)




def paso5_client_alive():
    print()
    print("="*100)
    print("[PASO 6]: Configurar ClientAliveInterval y ClientAliveCountMax.")
    print("="*100)
    print()

    paso="Paso 6"

    print("[INFO]: Configuración de timeout de sesiones inactivas:")
    print("         - ClientAliveInterval = 300 segundos")
    print("         - ClientAliveCountMax = 3 segundos")
    print("         - Timeout total: 300 x 3 = 900 segundos")
    print()

    exito1=configurar_directiva_ssh("ClientAliveInterval", "300", paso)
    exito2=configurar_directiva_ssh("ClientAliveCountMax", "3", paso)

    if exito1 and exito2:
        recargar_ssh(paso)


def paso6_hostbased_auth():
    print()
    print("="*100)
    print("[PASO 7]: Deshabilitar HostbasedAuthentication")
    print("="*100)
    print()

    paso="Paso 7"

    if configurar_directiva_ssh("HostbasedAuthentication", "no", paso):
        recargar_ssh(paso)

def paso7_ignore_rhosts():
    print()
    print("="*100)
    print("[PASO 6]: Configurar ClientAliveInterval y ClientAliveCountMax.")
    print("="*100)
    print()

    paso="Paso 8"

    if configurar_directiva_ssh("IgnoreRhosts", "yes", paso):
        recargar_ssh(paso)


def paso8_strict_modes():
    print()
    print("="*100)
    print("[PASO 9]: Habilitar StrictModes")
    print("="*100)
    print()

    paso="Paso 9"

    if configurar_directiva_ssh("StrictModes", "yes", paso):
        recargar_ssh(paso)


def paso9_permit_user_environment():
    print()
    print("="*100)
    print("[PASO 10]: Deshabilitar PermitUserEnvironment")
    print("="*100)
    print()

    paso="Paso 10"

    if configurar_directiva_ssh("PermitUserEnvironment", "no", paso):
        recargar_ssh(paso)


def paso10_print_last_log():
    print()
    print("="*100)
    print("[PASO 11]: Habilitar PrintLastLog")
    print("="*100)
    print()

    paso="Paso 11"

    if configurar_directiva_ssh("PrintLastLog", "yes", paso):
        recargar_ssh(paso)



        
def mostar_menu():
    print()
    print("="*100)
    print("Hardening: Conexiones SSH (Secure Shell)")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Cambiar el puerto SSH")
    print("     2. Restringir acceso por usuarios (AllowUsers)")
    print("     3. Deshabilitar autenticación GSSAPI")
    print("     4. Configurar LoginGraceTime (30s)")
    print("     5. Configurar ClientAliveInterval y ClientAliveCountMax")
    print("     6. Deshabilitar HostbasedAuthentication")
    print("     7. Configurar IgnoreRhosts")
    print("     8. Habilitar StrictModes")
    print("     9. Deshabilitar PermitUserEnvironment")
    print("     10. Habilitar PrintLastLog")

    print()
    print("     q. Salir")
    print()

def main():

    comprobar_root()
    configurar_logging(LOG_FILE)

    while True:
        mostar_menu()
        opcion=input("Selecciona una opción: ").strip().lower()

        match opcion:
            case "1":
                paso1_cambiar_puertos()
                volver_al_menu()
            case "2":
                paso2_allow_users()
                volver_al_menu()
            case "3":
                paso3_deshabilitar_gssapi()
                volver_al_menu()
            case "4":
                paso4_login_grace_time()
                volver_al_menu()
            case "5":
                paso5_client_alive()
                volver_al_menu()
            case "6":
                paso6_hostbased_auth()
                volver_al_menu()
            case "7":
                paso7_ignore_rhosts()
                volver_al_menu()
            case "8":
                paso8_strict_modes()
                volver_al_menu()
            case "9":
                paso9_permit_user_environment()
                volver_al_menu()
            case "10":
                paso10_print_last_log()
                volver_al_menu()
            case "q":
                print("\n[INFO]: Saliendo del script.")
                sys.exit(0)
            case _:
                print("[ERROR]: Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()
