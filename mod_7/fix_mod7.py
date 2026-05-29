#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, registrar_errores, comprobar_root,
                   ejecutar_comando, ejecutar_comando_check,
                   volver_al_menu, leer_fichero, escribir_fichero)


LOG_FILE="/var/log/hardening/modulo7_fix.log"

SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"
SYSCTL_CABECERA="""\
#===================================================================================================
# 99-hardening.conf - Parámetros de hardening del kernel
#===================================================================================================
# Generado automáticamente por fix_mod7.py
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#
# Para aplicar los cambios manualmente: sudo sysctl -p {conf}
#===================================================================================================
""".format(conf=SYSCTL_CONF)


#Funciones auxiliares

def obtener_valor_sysctl(parametro):
    """
    Obtiene el valor actual de un parámetro sysctl.

    Args:
        parametro (str): Nombre del parámetro

    Return:
        str o None: Valor actual del parámetro, o None si no existe
    """
    rc, salida, _= ejecutar_comando_check(["sysctl", "-n", parametro])
    if rc==0 and salida.strip():
        return salida.strip()
    return None



def persistir_sysctl(parametro, valor):
    """
    Añade o actualiza un parámetro en el fichero de configuración persistente
    /etc/sysctl.d/99-hardening.conf

    Si el fichero no existe, lo crea con la cabecera.
    Si el parámetro ya existe, lo actualiza.
    Si el parámetro no existe, lo añade al final.

    Args:
        parametro (str): Nombre del parámetro sysctl
        valor (str): Valor a establecer
    
    Return:
        None
    """
    contenido=leer_fichero(SYSCTL_CONF)
    if contenido is None:
        contenido=SYSCTL_CABECERA

    lineas=contenido.splitlines()
    encontrado=False
    
    for i, linea in enumerate(lineas):
        limpia=linea.strip()
        if limpia.startswith("#") or not limpia:
            continue

        if limpia.split("=")[0].strip() == parametro:
            lineas[i]=f"{parametro} = {valor}"
            encontrado=True
            break
    
    if not encontrado:
        lineas.append(f"{parametro} = {valor}")

    nuevoContenido="\n".join(lineas)
    if not nuevoContenido.endswith("\n"):
        nuevoContenido+="\n"

    escribir_fichero(SYSCTL_CONF, nuevoContenido, permisos=0o644, paso="General")



def aplicar_sysctl(parametro, valor, paso="General"):
    """
    Aplicar un parámetro sysctl en tiempo real y lo registra en el fichero
    de configuración persistente.

    Args:
        parametro (str): Nombre del parámetro sysctl
        valor (str): Valor a establecer
        paso (str): Identificador del paso para el log

    Retorna:
        bool: True si se aplicó correctamente, False en caso de error
    """
    valorActual=obtener_valor_sysctl(parametro)

    if valorActual==valor:
        print(f"[CORRECTO]: {parametro} = {valor} (ya configurado).")
        persistir_sysctl(parametro, valor)
        return True
    
    rc, _, stderr=ejecutar_comando_check(["sysctl", "-w", f"{parametro}={valor}"])

    if rc!=0:
        registrar_errores(paso, f"No se pudo aplicar {parametro}={valor}: "
                          f"{stderr.strip()}")
        print(f"[ERROR]: No se pudo aplicar {parametro}={valor}")
        return False

    print(f"[CORRECTO]: {parametro}: {valorActual} -> {valor}")

    persistir_sysctl(parametro, valor)
    return True


def paso1_syn_cookies():
    print()
    print("="*100)
    print("[PASO 1]: Habilitar protección SYN cookies.")
    print("="*100)
    print()

    paso="Paso 1"

    aplicar_sysctl("net.ipv4.tcp_syncookies", "1", paso)

def paso2_source_routing():
    print()
    print("="*100)
    print("[PASO 2]: Deshabilitar enrutamiento de origen IP.")
    print("="*100)
    print()

    paso="Paso 2"

    parametros=[
        "net.ipv4.conf.all.accept_source_route",
        "net.ipv4.conf.default.accept_source_route",
    ]

    for param in parametros:
        aplicar_sysctl(param, "0", paso)


def paso3_icmp_redirects():
    print()
    print("="*100)
    print("[PASO 3]: Deshabilitar redirecciones ICMP.")
    print("="*100)
    print()

    paso="Paso 3"

    parametros=[
        # No aceptar redirecciones ICMP de entrada
        ("net.ipv4.conf.all.accept_redirect", "0"),
        ("net.ipv4.conf.default.accept_redirects", "0"),
        # No aceptar redirecciones ICMP de salida
        ("net.ipv4.conf.all.send_redirects", "0"),
        ("net.ipv4.conf.default.send_redirects", "0"),
        # No aceptar redirecciones ICMP seguras
        ("net.ipv4.conf.all.secure_redirects", "0"),
        ("net.ipv4.conf.default.secure_redirects", "0"),
    ]

    for param, valor in parametros:
        aplicar_sysctl(param, valor, paso)


def paso4_icmp_bogus():
    print()
    print("="*100)
    print("[PASO 4]: Protección contra mensajes ICMP erróneos.")
    print("="*100)
    print()

    paso="Paso 4"

    aplicar_sysctl("net.ipv4.icmp_ignore_bogus_error_responses","1", paso)


def paso5_exec_shield():
    print()
    print("="*100)
    print("[PASO 5]: Exec-Shield")
    print("="*100)
    print()

    paso="Paso 5"

    #ASLR nivel 2= aleatorizar stack, heap, mmap, vdso
    aplicar_sysctl("kernel.randomize_va_space", "2", paso)

    # kptr_restrict=1 -> ocultar punteros del kernel a usuarios no-root
    aplicar_sysctl("kernel.kptr_restrict", "1", paso)


def paso6_log_martians():
    print()
    print("="*100)
    print("[PASO 6]: Registro de paquetes marcianos")
    print("="*100)
    print()

    paso="Paso 6"

    aplicar_sysctl("net.ipv4.conf.all.log_martians", "1", paso)
    aplicar_sysctl("net.ipv4.conf.default.log_martians", "1", paso)


def paso7_icmp_echo_broadcast():
    print()
    print("="*100)
    print("[PASO 7]: Ignorar echo broadcasts ICMP")
    print("="*100)
    print()

    paso="Paso 7"

    aplicar_sysctl("net.ipv4.icmp_echo_ignore_broadcasts", "1", paso)


def paso8_desactivar_ipv6():
    print()
    print("="*100)
    print("[PASO 8]: Desactivar IPv6 (si no se usa)")
    print("="*100)
    print()

    paso="Paso 8"

    valorActual=obtener_valor_sysctl("net.ipv6.conf.all.disable_ipv6")

    if valorActual=="1":
        print("[CORRECTO]: IPv6 ya está desactivado.")
        persistir_sysctl("net.ipv6.conf.all.disable_ipv6", "1")
        persistir_sysctl("net.ipv6.conf.default.disable_ipv6", "1")
        persistir_sysctl("net.ipv6.conf.lo.disable_ipv6", "1")
        return

    print("[INFO]: Verificando si hay servicios escuchando en IPv6...")
    print()

    rc, salida, _ = ejecutar_comando_check(["ss", "-tlnp6"])

    serviciosIPv6=[]
    for linea in salida.strip().splitlines():
        if linea.startswith("State") or not linea.strip():
            continue
        serviciosIPv6.append(linea.strip())
    
    if serviciosIPv6:
        print(f"[AVISO]: Se han detectado {len(serviciosIPv6)} servicio(s) escuchando en IPv6: ")
        print()
        for srv in serviciosIPv6:
            campos=srv.split()
            if len(campos)>=4:
                direccion=campos[3]
                proceso=campos[5] if len(campos)>=6 else "(desconocido)"
                print(f"    - {direccion} {proceso}")
        print()
        print("[AVISO]: Desactivar IPv6 podría afectar a estos servicios.")
        resp=input("¿Desactivar IPv6 de todas formas? (s/N): ").strip().lower()

        if resp!="s":
            print("[INFO]: IPv6 no se ha desactivado.")
            return
    else:
        print("[CORRECTO]: No hay servicios escuchando exclusivamente en IPv6.")
        print()

    print("[INFO]: Desactivando IPv6...")
    aplicar_sysctl("net.ipv6.conf.all.disable_ipv6", "1", paso=paso)
    aplicar_sysctl("net.ipv6.conf.default.disable_ipv6", "1", paso=paso)
    aplicar_sysctl("net.ipv6.conf.lo.disable_ipv6", "1", paso=paso)
    print()
    print("[CORRECTO]: IPv6 desactivado.")


def mostar_menu():
    print()
    print("="*100)
    print("Hardening: Parámetros del Kernel)")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Habilitar protección SYN cookies")
    print("     2. Deshabilitar enrutamiento de origen IP")
    print("     3. Deshabilitar redirecciones ICMP")
    print("     4. Protección contra mensajes ICMP erróneos")
    print("     5. Exec-Shield")
    print("     6. Registro de paquetes marcianos")
    print("     7. Ignorar echo broadcasts ICMP")
    print("     8. Desactivar IPv6 (si no se usa)")
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
                paso1_syn_cookies()
                volver_al_menu()
            case "2":
                paso2_source_routing()
                volver_al_menu()
            case "3":
                paso3_icmp_redirects()
                volver_al_menu()
            case "4":
                paso4_icmp_bogus()
                volver_al_menu()
            case "5":
                paso5_exec_shield()
                volver_al_menu()
            case "6":
                paso6_log_martians()
                volver_al_menu()
            case "7":
                paso7_icmp_echo_broadcast()
                volver_al_menu()
            case "8":
                paso8_desactivar_ipv6()
                volver_al_menu()
            case "q":
                print("\n[INFO]: Saliendo del script.")
                sys.exit(0)
            case _:
                print("[ERROR]: Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()
