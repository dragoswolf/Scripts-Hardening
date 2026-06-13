#!/usr/bin/env python3
#=========================================================================================================
# fix_mod6.py - Script de fortificación para el módulo 6 - Sistemas de ficheros
#=========================================================================================================
# Este script implementa las siguientes medidas de seguridad:
#
#   Paso 1: Aduditar y deshabilitar binarios SUID/SGID innecesarios
#   Paso 2: Auditoría del filesystem (sticky bit, ficheros huérfanos, 
#           ficheros world-writtable)
#   Paso 3: Configurar opciones de montaje (/tmp, /dev/shm)
#   Paso 4: Proteger/desproteger ficheros críticos con chattr
#
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo6_fix.log
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================


import os
import sys
import stat

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, 
                   registrar_errores, 
                   comprobar_root,
                   ejecutar_comando, 
                   ejecutar_comando_check, 
                   volver_al_menu,
                   leer_fichero, 
                   escribir_fichero,
                   print_info,
                   print_aviso,
                   print_correcto,
                   print_error)


LOG_FILE="/var/log/hardening/modulo6_fix.log"

WHITELIST_SUID=[
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/gpasswd",
    "/usr/bin/mount",
    "usr/bin/newgrp",
    "/usr/bin/passwd",
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/umount",
    "/usr/lib/dpus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/libexec/polkit-agent-helper-1",
]

WHITELIST_SGID=[
    "/usr/bin/chage",
    "/usr/bin/crontab",
    "/usr/bin/expiry",
    "/usr/bin/ssh-agent",
    "/usr/bin/wall",
    "/usr/bin/write",
    "/usr/sbin/pam_extrausers_chkpwd",
    "/usr/sbin/unix_chkpwd",
]

DIRECTORIOS_EXCLUIDOS_WW=[
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run",
    "/proc",
    "/sys",
    "/dev",
]

FSTAB="/etc/fstab"


FICHEROS_CRITICOS=[
    "/etc/fstab",
]


def paso1_auditar_suid_sgid():
    """
    Busca binarios SUID/SGID en el sistema y permite eliminar los que
    no están en la whitelist.
    """
    print()
    print("="*100)
    print("[PASO 1]: Auditar binarios SUID/SGID.")
    print("="*100)
    print_info("Busca binarios con bit SUID/SGID en el sistema.")
    print_info("Ofrece eliminar el bit de los que no son necesarios.")
    print()

    paso="Paso 1"

    # 1a. Buscar binarios SUID y dar la opción de eliminarlos
    print_info("Buscando binarios con bit SUID...")

    rc, salida, _ = ejecutar_comando_check(["find", "/", "-xdev", "-type", "f", "-perm", "-4000",
                                            "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"])
    
    suidEncontrados=[l.strip() for l in salida.splitlines() if l.strip()]
    suidSospechosos = [b for b in suidEncontrados if b not in WHITELIST_SUID]

    print(f"    Binarios SUID encontrados:  {len(suidEncontrados)}")
    print(f"    En whitelist:               {len(suidEncontrados)-len(suidSospechosos)}")
    print(f"    Sospechosos:                {len(suidSospechosos)}")

    if suidSospechosos:
        print()
        print_aviso("Binarios SUID no reconocidos: ")

        for i, binario in enumerate(suidSospechosos, 1):
            print(f"    {i}. {binario}")

        print()
        resp=input("¿Eliminar el bit SID de los binarios sospechosos? (s/N): ").strip().lower()

        if resp=="s":
            for binario in suidSospechosos:
                print(f"    Eliminando SUID de {binario}....")
                ejecutar_comando(["chmod", "u-s", binario], f"eliminar SUID de {binario}", paso)
            
            print_correcto("Bits SUID eliminados.")
        else:
            print_info("No se han modificado los binarios SUID.")
    else:
        print_correcto("No hay binarios SUID sospechosos.")

    # 1b. Buscar binarios SGID y dar la opción de eliminarlos
    print_info("Buscando binarios con bit SGID...")

    rc, salida, _ = ejecutar_comando_check(["find", "/", "-xdev", "-type", "f", "-perm", "-2000",
                                            "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"])
    
    sgidEncontrados=[l.strip() for l in salida.splitlines() if l.strip()]
    sgidSospechosos = [b for b in sgidEncontrados if b not in WHITELIST_SGID]

    print(f"    Binarios SGID encontrados:  {len(sgidEncontrados)}")
    print(f"    En whitelist:               {len(sgidEncontrados)-len(sgidSospechosos)}")
    print(f"    Sospechosos:                {len(sgidSospechosos)}")

    if sgidSospechosos:
        print()
        print_aviso("Binarios SGID no reconocidos: ")

        for i, binario in enumerate(sgidSospechosos):
            print(f"    {i}. {binario}")

        print()
        resp=input("¿Eliminar el bit SID de los binarios sospechosos? (s/N): ").strip().lower()

        if resp=="s":
            for binario in sgidSospechosos:
                print(f"    Eliminando SGID de {binario}....")
                ejecutar_comando(["chmod", "g-s", binario], f"eliminar SGID de {binario}", paso)
            
            print_correcto("Bits SUID eliminados.")
        else:
            print_info("No se han modificado los binarios SUID.")
    else:
        print_correcto("No hay binarios SUID sospechosos.")


def paso2_auditoria_filesystem():
    """
    Realiza auditoría general del filesystem para asegurarse de que cada fichero/directorio
    solo puede ser modificado por su propietario.
    """
    print()
    print("="*100)
    print("[PASO 2]: Auditoría del filesystem.")
    print("="*100)
    print_info("Audita el filesystem buscando directorios world-writable, sin sticky bit,")
    print_info(" y ficheros sin propietario válido.")
    print_info("Les añade el sticky bit para que solo los propietarios puedan realizar cambios.")
    print()


    paso="Paso 2"


    # 2a. Directorios world-writable sin sticky bit
    print_info("Buscando directorios world-writable sin sticky bit...")
    rc, salida, _ = ejecutar_comando_check(["find", "/", "-xdev", "-type", "d", "-perm", 
                                            "-0002", "!", "-perm", "-1000", "-not", "-path",
                                            "/proc/*", "-not", "-path", "/sys/*"])
    
    dirsSinSticky=[l.strip() for l in salida.splitlines() if l.strip()]

    if dirsSinSticky:
        print_aviso(f"{len(dirsSinSticky)} directorio(s) world-writable sin sticky bit:")
        for d in dirsSinSticky:
            print(f"    - {d}")
    
        print()
        resp=input("¿Añadir sticky bit a estos directorios? (s/N): ").strip().lower()

        if resp=="s":
            for d in dirsSinSticky:
                ejecutar_comando(["chmod", "+t", d], f"añadir sticky bit a {d}", paso)
            print_correcto("Sticky bit añadido.")
        else:
            print_info("No se han modificado los directorios.")
    else:
        print_correcto("Todos los directorios world-writable tienen sticky bit.")

    # 2b. Ficheros sin propietario válido
    print()
    print("Buscando icheros sin propietario válido (huérfanos)...")
    print()

    rc, salida, _=ejecutar_comando_check(["find", "/", "-xdev", "-nouser", "-o", "-nogroup", "-not", 
                                          "-path", "/proc/*", "-not", "-path", "/sys/*"])


    huerfanos=[l.strip() for l in salida.splitlines() if l.strip()]

    if huerfanos:
        maxMostrar=20
        print_aviso(f"{len(huerfanos)} fichero(s) sin propietario válido:")
        for f in huerfanos[:maxMostrar]:
            print(f"    - {f}")
        if len(huerfanos)>maxMostrar:
            print(f"    ... y {len(huerfanos)-maxMostrar} más.")

        print()
        print_info("Revisa estos ficheros manualmente.")
        print("        Puedes asignarles un propietario con:")
        print("        sudo chown root:root <fichero>")
    else:
        print_correcto("No hay ficheros sin propietario válido.")

    # 2c. Ficheros world-writable.
    print()
    print("Buscando ficheros world-writable.")
    print()

    rc, salida, _ =ejecutar_comando_check(["find", "/", "-xdev", "-type", "f", "-perm",
                                           "-0002", "-not", "-path", "/proc/*", "-not",
                                           "-path", "/sys/*"])
    
    wwFicheros=[]
    for linea in salida.splitlines():
        linea=linea.strip()
        if not linea:
            continue
        excluido = False

        for dirExcluido in DIRECTORIOS_EXCLUIDOS_WW:
            if linea.startswith(dirExcluido+"/"):
                excluido=True
                break
            if not excluido:
                wwFicheros.append(linea)

    if wwFicheros:
        maxMostrar=20
        print_aviso(f"{len(wwFicheros)} fichero(s) world-writable:")
        for f in wwFicheros[:maxMostrar]:
            print(f"    - {f}")

        if len(wwFicheros)>maxMostrar:
            print(f"    ... y {len(wwFicheros)-maxMostrar} más.")

        print()
        resp=input("¿Eliminar el permiso de escritura para 'otros' de estos ficheros? (s/N): ").strip().lower()

        if resp=="s":
            for f in wwFicheros:
                ejecutar_comando(["chmod", "o-w", f], f"eliminar world-writable de {f}", paso)
            
            print_correcto("Permisos restringidos.")
        else:
            print_info("No se han modificado los ficheros.")
    else:
        print_correcto("No hay ficheros world-writable fuera de directorios temporales.")


def paso3_opciones_montaje():
    """
    Configura las opciones de montaje nodev, nosuid, noexec en /tmp
    y /dev/shm a través de /etc/fstab.
    """
    print()
    print("="*100)
    print("[PASO 3]: Configurar opciones de montaje.")
    print("="*100)
    print_info("Configura opciones restrictivas en directorios para impedir ejecutar binarios o")
    print_info("explotar bits SUID en estos directorios.")
    print()

    paso="Paso 3"

    # 3a. Definir las opciones requeridas para cada punto de montaje
    montajes={
        "/tmp": ["nodev", "nosuid", "noexec"],
        "/dev/shm": ["nodev", "nosuid", "noexec"],
    }

    contenido=leer_fichero(FSTAB, paso=paso)

    if contenido is None:
        registrar_errores(paso, f"No se pudo leer {FSTAB}")
        return
    
    lineas=contenido.splitlines()
    modificado=False

    for punto, opcionesRequeridas in montajes.items():
        # 3b. Comprobar si existe entradas en fstab
        print_info(f"Verificando opciones de montaje para {punto}...")

        lineaEncontrada=-1

        for i, linea in enumerate(lineas):
            limpia=linea.strip()
            if limpia.startswith("#") or not limpia:
                continue
            campos=limpia.split()
            if len(campos)>=4 and campos[1]==punto:
                lineaEncontrada=i
                break

        if lineaEncontrada==-1:
            # 3c. Si no existe, añadir entrada en FSTAB
            print_aviso(f"{punto} no tiene entrada en {FSTAB}.")

            if punto=="/tmp":
                print_info(f"Añadiendo entrada para {punto} en {FSTAB}...")
                opciones=",".join(["defaults"] + opcionesRequeridas)
                nuevaLinea=f"tmpfs  {punto}  tmpfs  {opciones}  0  0"
                lineas.append(nuevaLinea)
                modificado=True
                print_correcto(f"Entrada añadida: {nuevaLinea}")
            elif punto=="/dev/shm":
                print_info(f"Añadiendo entrada para {punto} en {FSTAB}...")
                opciones=",".join(["defaults"]+opcionesRequeridas)
                nuevaLinea=f"tmpfs  {punto}  tmpfs  {opciones}  0  0"
                lineas.append(nuevaLinea)
                modificado=True
                print_correcto(f"Entrada añadida: {nuevaLinea}")
        else:
            campos=lineas[lineaEncontrada].split()
            opcionesActuales=campos[3].split(",")
            opcionesFaltantes=[o for o in opcionesRequeridas if o not in opcionesActuales]

            if opcionesFaltantes:
                print_aviso(f"Faltan opciones: {', '.join(opcionesFaltantes)}")
                nuevasOpciones=opcionesActuales+opcionesFaltantes
                campos[3]=",".join(nuevasOpciones)
                lineas[lineaEncontrada]="\t".join(campos)
                modificado=True
                print_correcto(f"Opciones actualizadas: {campos[3]}")
            else:
                print_correcto(f"{punto} ya tiene {', '.join(opcionesRequeridas)}")
        
    if modificado:
        # 3d. Añadir cambios y remontar puntos de montaje
        nuevoContenido="\n".join(lineas)
        if not nuevoContenido.endswith("\n"):
            nuevoContenido+="\n"
        if escribir_fichero(FSTAB, nuevoContenido, paso=paso):
            print()
            print_info(f"{FSTAB} actualizado. Aplicando cambios...")
            for punto in montajes:
                rc, _, _= ejecutar_comando_check(["findmnt", "-n", punto])

                if rc==0:
                    #Ya está montado, remontar
                    ejecutar_comando(["mount", "-o", "remount", punto], f"remontar {punto}", paso)
                else:
                    # No está montado, montar
                    ejecutar_comando(["mount", punto], f"montar {punto}", paso)
            print_correcto("Puntos de montaje configurados con las nuevas opciones.")
    else:
        print()
        print_correcto("Todas las opciones de montaje están correctas.")



def paso4_chattr_ficheros():
    """
    Permite bloquear o desbloquear los ficheros críticos del sistema
    con el atributo inmutable (chattr +i/-i)
    """
    print()
    print("="*100)
    print("[PASO 4]: Proteger ficheros críticos.")
    print("="*100)
    print_info("Permite bloquear o desbloquear ficheros críticos del sistema.")
    print_info("Impide modificaciones incluso por root.")
    print()

    paso="Paso 4"

    # 4a. Muestra el estado actual de los ficheros.
    print_info("Estado actual de los ficheros críticos.")
    print()

    estadoActual={}

    for fichero in FICHEROS_CRITICOS:
        rc, salida, _=ejecutar_comando_check(["lsattr", fichero])

        if rc==0 and salida.strip():
            atributos=salida.split()[0]
            esInmutable="i" in atributos
            estadoActual[fichero]=esInmutable
            nombre=os.path.basename(fichero)

            if esInmutable:
                print(f" \033[92m[BLOQUEADO]\033[0m  {nombre}")
            else:
                print(f" \033[93m[DESBLOQUEADO]\033[0m  {nombre}")
        else:
            estadoActual[fichero]=False
            nombre=os.path.basename(fichero)
            print_error(f"No se pudo leer: {nombre}")

    print()
    print("¿Qué deseas hacer?")
    print()
    print(" 1) Bloquear - Protege contra modificaciones")
    print(" 2) Desbloquear - Permite gestión de usuarios/grupos")
    print(" 0) Saltar este paso")
    print()

    # 4b. Realiza la opción deseada
    opcion=input("Selecciona una opción [0-2]: ").strip()

    if opcion=="1":
        print()
        print("[INFO] Bloqueando ficheros críticos...")
        for fichero in FICHEROS_CRITICOS:
            nombre=os.path.basename(fichero)
            if estadoActual.get(fichero, False):
                print_correcto(f"{nombre} ya está bloqueado.")
            else:
                ejecutar_comando(["chattr", "+i", fichero], f"bloquear {fichero}", paso)
                print_correcto(f"{nombre} bloqueado.")

        print()
        print_correcto("Ficheros críticos protegidos.")
        print_info("Recuerda desbloquear antes de gestionar usuarios o grupos.")
    
    elif opcion=="2":
        print()
        print_info("Desbloqueando ficheros críticos...")
        for fichero in FICHEROS_CRITICOS:
            nombre=os.path.basename(fichero)
            if not estadoActual.get(fichero, False):
                print_correcto(f"{nombre} ya está desbloqueado.")
            else:
                ejecutar_comando(["chattr", "-i", fichero], f"desbloquear {fichero}", paso)
                print_correcto(f"{nombre} desbloqueado.")
        print()
        print_correcto("Ficheros desbloqueados. Ya puede gestionar usuarios y grupos.")
        print_aviso("No olvide volver a bloquearlos cuando termine.")
    else:
        print_info("Paso omitido.")


def mostar_menu():
    print()
    print("="*100)
    print("Hardening: Sistema de Ficheros)")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Auditar binarios SUID/SGID")
    print("     2. Auditar filesystem")
    print("     3. Configurar opciones de montaje")
    print("     4. Bloquear/desbloquear ficheros críticos.")
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
                paso1_auditar_suid_sgid()
                volver_al_menu()
            case "2":
                paso2_auditoria_filesystem()
                volver_al_menu()
            case "3":
                paso3_opciones_montaje()
                volver_al_menu()
            case "4":
                paso4_chattr_ficheros()
                volver_al_menu()
            case "q":
                print_info("Saliendo del script.")
                sys.exit(0)
            case _:
                print_error("Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()



