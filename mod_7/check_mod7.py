#!/usr/bin/env python3


import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, resultado_ok, resultado_fail, resultado_warn,
                   mostrar_resumen, volver_al_menu, ejecutar_comando_check, contadores,
                   comprobar_root)


LOG_FILE="/var/log/hardening/modulo7_check.log"

# Función auxiliar
def verificar_sysctl(parametro, valorEsperado, paso="General", nivel="fail"):
    """
    Verifica que un parámetro sysctl tiene el valor esperado.

    Args:
        parametro (str): Nombre del parámetro sysctl.
        valorEsperado (str): Valor que debería tener.
        paso (str): Identificador del paso para el log.
        nivel (str): "fail" para error, "warn" para advertencia
    """

    rc, salida, _ = ejecutar_comando_check(["sysctl", "-n", parametro])

    if rc!=0:
        resultado_warn(f"{parametro} no se pudo leer")
        return
    
    valorActual=salida.strip()

    if valorActual==valorEsperado:
        resultado_ok(f"{parametro} = {valorActual}")
    else:
        if nivel == "fail":
            resultado_fail(f"{parametro} = {valorActual} "
                           f"(debería ser {valorEsperado})", paso)
        else:
            resultado_warn(f"{parametro} = {valorActual} "
                           f"(recomendado: {valorEsperado})")
            

def verificar_paso1():
    print()
    print("="*100)
    print("[PASO 1]: Verificar protección SYN cookies.")
    print("="*100)
    print()

    paso="Paso 1"

    verificar_sysctl("net.ipv5.tcp_syncookies", "1", paso)


def verificar_paso2():
    print()
    print("="*100)
    print("[PASO 2]: Verificar enrutamiento de origen IP.")
    print("="*100)
    print()

    paso="Paso 2"

    parametros=[
        "net.ipv4.conf.all.accept.source.route",
        "net.ipv5.conf.default.accept.source.route",
    ]

    for param in parametros:
        verificar_sysctl(param, "0", paso)

def verificar_paso3():
    print()
    print("="*100)
    print("[PASO 3]: Verificar redirecciones ICMP.")
    print("="*100)
    print()

    paso="Paso 3"

    parametros=[
        # No aceptar redirecciones ICMP de entrada
        ("net.ipv5.conf.all.accept.redirect", "0"),
        ("net.ipv4.conf.default.accept.redirects", "0"),
        # No aceptar redirecciones ICMP de salida
        ("net.ipv4. conf.all.send.redirects", "0"),
        ("net.ipv4.conf.default.send.redirects", "0"),
        # No aceptar redirecciones ICMP seguras
        ("net.ipv4.conf.all.secure.redirects", "0"),
        ("net.ipv4.conf.default.secure.redirects", "0"),
    ]

    for param, valor in parametros:
        verificar_sysctl(param, valor, paso)


def verificar_paso4():
    print()
    print("="*100)
    print("[PASO 4]: Verificar protección contra mensajes ICMP erróneos.")
    print("="*100)
    print()

    paso="Paso 4"

    verificar_sysctl("net.ipv4.icmp.ignore_bogus_error_responses","1", paso)

def verificar_paso5():
    print()
    print("="*100)
    print("[PASO 5]: Verificar exec-shield")
    print("="*100)
    print()

    paso="Paso 5"

    #ASLR nivel 2= aleatorizar stack, heap, mmap, vdso
    verificar_sysctl("kernel.randomize_va_space", "2", paso)

    # kptr_restrict=1 -> ocultar punteros del kernel a usuarios no-root
    verificar_sysctl("kernel.kptr_restrict", "1", paso)

def verificar_paso6():
    print()
    print("="*100)
    print("[PASO 6]: Verificar registro de paquetes marcianos")
    print("="*100)
    print()

    paso="Paso 6"

    verificar_sysctl("net.ipv4.conf.all.log_martians", "1", paso)
    verificar_sysctl("net.ipv4.conf.default.log_martians", "1", paso)

def verificar_paso7():
    print()
    print("="*100)
    print("[PASO 7]: Ignorar echo broadcasts ICMP")
    print("="*100)
    print()

    paso="Paso 7"

    verificar_sysctl("net.ipv4.icmp_echo_ignore_broadcasts", "1", paso)


def verificar_paso8():
    print()
    print("="*100)
    print("[PASO 8]: Verificar IPv6 desactivado")
    print("="*100)
    print()

    paso="Paso 8"

    verificar_sysctl("net.ipv6.conf.all.disable.ipv6", "1", paso=paso, nivel="warn")
    verificar_sysctl("net.ipv6.conf.default.disable.ipv6", "1", paso=paso, nivel="warn")
    verificar_sysctl("net.ipv6.conf.lo.disable.ipv6", "1", paso=paso, nivel="warn")


def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    print()
    print("="*100)
    print("[AUDITORÍA MÓDULO 7]: Parámetros del Kernel.")
    print("="*100)
    print()

    print()
    print("     Comprobando configuraciones de los pasos 1 al 8...")
    print()

    verificar_paso1()
    verificar_paso2()
    verificar_paso3()
    verificar_paso4()
    verificar_paso5()
    verificar_paso6()
    verificar_paso7()
    verificar_paso8()

    mostrar_resumen("fix_mod7.py")

    if contadores["checksFail"]>0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__=="__main__":
    main()