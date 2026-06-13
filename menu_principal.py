#!/usr/bin/env python3
#=========================================================================================================
# menu_principal.py - Menú principal de la aplicación
#=========================================================================================================
# Interfaz centralizada que da acceso a todos los módulos de hardening.
# Al salir de un módulo (fix), ejecuta automáticamente su script de verificación (check)
#
# IMPORTANTE: Debe ejecutarse como root (sudo)
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================

import os
import sys
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from utils import(print_aviso,
                  print_correcto,
                  print_info,
                  print_error,
                  comprobar_root,
                  volver_al_menu)



#=========================================================================================================
# CONSTANTES
#=========================================================================================================
# Directorio de los módulos
BASE_DIR=os.path.dirname(os.path.abspath(__file__))

# Información de los módulos
MODULOS=[
    {
        "numero": 1,
        "nombre": "Seguridad en acceso al hardware",
        "fix": "mod_1/fix_mod1.py",
        "check": "mod_1/check_mod1.py"
    },
    {
        "numero": 2,
        "nombre": "Hardening General de SO",
        "fix": "mod_2/fix_mod2.py",
        "check": "mod_2/check_mod2.py"
    },
    {
        "numero": 3,
        "nombre": "Usuarios y Grupos",
        "fix": "mod_3/fix_mod3.py",
        "check": "mod_3/check_mod3.py"
    },
    {
        "numero": 4,
        "nombre": "PAM (Pluggable Authentication Modules)",
        "fix": "mod_4/fix_mod4.py",
        "check": "mod_4/check_mod4.py"
    },
    {
        "numero": 5,
        "nombre": "SSH (Secure Shell)",
        "fix": "mod_5/fix_mod5.py",
        "check": "mod_5/check_mod5.py"
    },
    {
        "numero": 6,
        "nombre": "Sistemas de ficheros",
        "fix": "mod_6/fix_mod6.py",
        "check": "mod_6/check_mod6.py"
    },
    {
        "numero": 7,
        "nombre": "Parámetros del Kernel",
        "fix": "mod_7/fix_mod7.py",
        "check": "mod_7/check_mod7.py"
    },
    {
        "numero": 8,
        "nombre": "AppArmor (Mandatory Access Control)",
        "fix": "mod_8/fix_mod8.py",
        "check": "mod_8/check_mod8.py"
    },
    {
        "numero": 9,
        "nombre": "Firewall (UFW)",
        "fix": "mod_9/fix_mod9.py",
        "check": "mod_9/check_mod9.py"
    },
    {
        "numero": 10,
        "nombre": "Configuración y Supervisión de logs",
        "fix": "mod_10/fix_mod10.py",
        "check": "mod_10/check_mod10.py"
    },
    {
        "numero": 11,
        "nombre": "Detección de Intrusos de Host (AIDE)",
        "fix": "mod_11/fix_mod11.py",
        "check": "mod_11/check_mod11.py"
    },
    {
        "numero": 12,
        "nombre": "Antimalware",
        "fix": "mod_12/fix_mod12.py",
        "check": "mod_12/check_mod12.py"
    },
    {
        "numero": 13,
        "nombre": "Copias de seguridad",
        "fix": "mod_13/fix_mod13.py",
        "check": "mod_13/check_mod13.py"
    },
]
#=========================================================================================================

#=========================================================================================================
# FUNCIONES AUXILIARES
#=========================================================================================================

def limpiar_pantalla():
    """
    Limpia la pantalla de la terminal
    """
    subprocess.run("clear", shell=True)


def ejecutar_script(ruta_relativa):
    """
    Ejecuta un script Python como subproceso.
    Devuelve el código de salida del script
    """

    ruta=os.path.join(BASE_DIR, ruta_relativa)
    if not os.path.isfile(ruta):
        print_error(f"Script no encontrado: {ruta}")
        return 1
    
    try:
        resultado=subprocess.run([sys.executable, ruta], cwd=BASE_DIR)
        return resultado.returncode
    except KeyboardInterrupt:
        print_info("Interrumpido por el usuario.")
        return 130
    

def mostrar_menu():
    """
    Muestra el menú principal con todos los módulos.
    """

    limpiar_pantalla()
    print()
    print("="*100)
    print("FORTIFICACIÓN INTEGRAL - Ubuntu Server 24.04.4 LTS")
    print("Menú Principal")
    print("="*100)
    print()

    for i, modulo in enumerate(MODULOS, 1):
        num=modulo["numero"]
        nombre=modulo["nombre"]
        print(f"    {i:>2}. Módulo {num}: {nombre}")
    
    print()
    print("     q. Salir")
    print()

def confirmar_check(nombre_modulo):
    """
    Pregunta al usuario si quiere ejecutar el check tras el fix
    """
    print()
    print("="*100)
    print()
    
    respuesta=input(f"¿Ejecutar verificación del módulo {nombre_modulo}? (s/n): ").strip().lower()

    return respuesta!="n"

def main():
    """
    Función principal. Muestra el menú, ejecuta el fix seleccionado y lanza el check automáticamente
    al terminar
    """

    comprobar_root()

    while True:
        mostrar_menu()
        opcion=input("Selecciona una opción: ").strip().lower()

        if opcion=="q":
            print_info("Saliendo del menú principal...")
            sys.exit(0)

        try:
            indice=int(opcion)-1
            if indice<0 or indice >= len(MODULOS):
                raise ValueError
        except ValueError:
            print_error("Opción no válida.")
            volver_al_menu()
            continue

        modulo=MODULOS[indice]
        nombre=f"{modulo['numero']}: {modulo['nombre']}"

        #Ejecutar fix
        limpiar_pantalla()
        print()
        print_info(f"Ejecutando fix del Módulo {nombre}")
        print()
        ejecutar_script(modulo["fix"])

        # Preguntar si ejecutar check
        if confirmar_check(nombre):
            limpiar_pantalla()
            print_info(f"Ejecutando verificación del Módulo {nombre}")
            print()
            ejecutar_script(modulo["check"])
            
        volver_al_menu()

            
if __name__=="__main__":
    main()
            


