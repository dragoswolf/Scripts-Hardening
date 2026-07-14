#!/usr/bin/env python3
#=========================================================================================================
# fix_mod7.py - Script de fortificación para el módulo 7 - Parámetros del Kernel
#=========================================================================================================
# Este script implementa las siguientes medidas de seguridad:
#
#   Paso 1: Habilitar protección SYN cookies
#   Paso 2: Deshabilitar enrutamiento de origen IP
#   Paso 3: Deshabilitar redirecciones ICMP
#   Paso 4: Protección contra mensajes ICMP erróneos
#   Paso 5: Exec-Shield
#   Paso 6: Registro de paquetes marcianos
#   Paso 7: Ignorar echo boradcasts ICMP
#   Paso 8: Desactivar IPv6 si no se usa.
#
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo7_fix.log
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, 
                   registrar_errores, 
                   comprobar_root,
                   ejecutar_comando_check,
                   volver_al_menu, 
                   leer_fichero, 
                   escribir_fichero,
                   print_info,
                   print_aviso,
                   print_correcto,
                   print_error
                   )


#=========================================================================================================
# CONSTANTES
#=========================================================================================================

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

#=========================================================================================================



#=========================================================================================================
# FUNCIONES AUXILIARES
#=========================================================================================================

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

    if os.path.isfile(SYSCTL_CONF):
        contenido=leer_fichero(SYSCTL_CONF)
    else:
        contenido = None

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
        print_correcto(f"{parametro} = {valor} (ya configurado).")
        persistir_sysctl(parametro, valor)
        return True
    
    rc, _, stderr=ejecutar_comando_check(["sysctl", "-w", f"{parametro}={valor}"])

    if rc!=0:
        registrar_errores(paso, f"No se pudo aplicar {parametro}={valor}: "
                          f"{stderr.strip()}")
        print_error(f"No se pudo aplicar {parametro}={valor}")
        return False

    print_correcto(f"{parametro}: {valorActual} -> {valor}")

    persistir_sysctl(parametro, valor)
    return True
#=========================================================================================================


def paso1_syn_cookies():
    """
    Habilita la protección SYN cookies para prevenir ataques SYN flood.
    """
    print()
    print("="*100)
    print("[PASO 1]: Habilitar protección SYN cookies.")
    print("="*100)
    print_info("Habilita SYN cookies para proteger contra ataques SYN flood.")
    print()

    paso="Paso 1"

    aplicar_sysctl("net.ipv4.tcp_syncookies", "1", paso)

def paso2_source_routing():
    """
    Deshabilita el enrutamiento de origen IP en todas las interfaces
    """
    print()
    print("="*100)
    print("[PASO 2]: Deshabilitar enrutamiento de origen IP.")
    print("="*100)
    print_info("Deshabilita el source routing IP, que permite al emisor\n" \
    "       especificar la ruta del paquete saltándose las tablas de enrutamiento.\n" \
    "       Previene ataques MITM")
    print()

    paso="Paso 2"

    parametros=[
        "net.ipv4.conf.all.accept_source_route",
        "net.ipv4.conf.default.accept_source_route",
    ]

    for param in parametros:
        aplicar_sysctl(param, "0", paso)


def paso3_icmp_redirects():
    """
    Deshabilita la aceptación y el envío de redirecciones ICMP. Previene así
    ataques donde un atacante envía mensajes ICMP Redirect falsos para redirigir
    tráfico.
    """
    print()
    print("="*100)
    print("[PASO 3]: Deshabilitar redirecciones ICMP.")
    print("="*100)
    print_info("Deshabilita la acceptación y el envío de redirecciones ICMP.\n" \
    "       Previene así ataques donde un atacante envía mensajes ICMP Redirect falsos\n" \
    "       para redirigir tráfico.")
    print()

    paso="Paso 3"

    parametros=[
        # No aceptar redirecciones ICMP de entrada
        ("net.ipv4.conf.all.accept_redirects", "0"),
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
    """
    Habilita la protección contra mensajes ICMP erróneos, ignorando las respuestas
    ICMP inválidas de routers mal configurados.
    """
    print()
    print("="*100)
    print("[PASO 4]: Protección contra mensajes ICMP erróneos.")
    print("="*100)
    print_info("Habilita la protección contra mensajes ICMP erróneos, ignorando\n" \
    "       las respuestas ICMP inválidas de routers mal configurados.")
    print()

    paso="Paso 4"

    aplicar_sysctl("net.ipv4.icmp_ignore_bogus_error_responses","1", paso)


def paso5_exec_shield():
    """
    Configura ASLR al máximo nivel (aleatoriza memoria) y activa kptr_restrict para
    ocultar direcciones del kernel a usuarios no privilegiados.
    """
    print()
    print("="*100)
    print("[PASO 5]: Exec-Shield")
    print("="*100)
    print_info("Configura ASLR al máximo nivel (aleatoriza memoria) y activa kptr_restrict\n" \
    "       para ocultar direcciones del kernel a usurios no privilegiados.")
    print()

    paso="Paso 5"

    # 5a. ASLR nivel 2= aleatorizar stack, heap, mmap, vdso
    aplicar_sysctl("kernel.randomize_va_space", "2", paso)

    # 5b. kptr_restrict=1 -> ocultar punteros del kernel a usuarios no-root
    aplicar_sysctl("kernel.kptr_restrict", "1", paso)


def paso6_log_martians():
    """
    Habilita el registro de paquetes marcianos (paquetes con direcciones IP imposibles
    o inesperadas). Permite detectar intentos de spoofing o errores de configuración
    de red.
    """
    print()
    print("="*100)
    print("[PASO 6]: Registro de paquetes marcianos")
    print("="*100)
    print_info("Habilita el registro de paquetes marcianos (paquetes con direcciones IP\n" \
    "       imposibles o inesperadas). Permite detectar intentos de spoofing o errores de configuración de red.")
    print()

    paso="Paso 6"

    aplicar_sysctl("net.ipv4.conf.all.log_martians", "1", paso)
    aplicar_sysctl("net.ipv4.conf.default.log_martians", "1", paso)


def paso7_icmp_echo_broadcast():
    """
    Configura el kernel para ignorar peticiones ICMP echo dirigidas a direcciones de broadcast.
    Previene que el servidor participe en algunos tipos de ataques (ej: Smurf).
    """
    print()
    print("="*100)
    print("[PASO 7]: Ignorar echo broadcasts ICMP")
    print("="*100)
    print_info("Configura el kernel para ignorar peticiones ICMP echo dirigidas a direcciones\n" \
    "       de broadcast. Previene que el servidor participe en algunos tipos de ataques (ej: Smurf)")
    print()

    paso="Paso 7"

    aplicar_sysctl("net.ipv4.icmp_echo_ignore_broadcasts", "1", paso)





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
            case "q":
                print_info("Saliendo del script.")
                sys.exit(0)
            case _:
                print_error("Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()
