#!/usr/bin/env python3


import os
import sys
import stat

sys.path.inser(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, registrar_errores, comprobar_root,
                   ejecutar_comando, ejecutar_comando_check, volver_al_menu,
                   leer_fichero, escribir_fichero)


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
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
]


def paso1_auditar_suid_sgid():
    print()
    print("="*100)
    print("[PASO 1]: Auditar binarios SUID/SGID.")
    print("="*100)
    print()

    paso="Paso 1"

    print("[INFO]: Buscando binarios con bit SUID...")

    rc, salida, _ = ejecutar_comando_check(["find", "/", "-xdev", "-type", "f", "-perm", "-4000",
                                            "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"])
    
    suidEncontrados=[l.strip() for l in salida.splitlines() if l.strip()]
    suidSospechosos = [b for b in suidEncontrados if b not in WHITELIST_SUID]

    print(f"    Binarios SUID encontrados:  {len(suidEncontrados)}")
    print(f"    En whitelist:               {len(suidEncontrados)-len(suidSospechosos)}")
    print(f"    Sospechosos:                {len(suidSospechosos)}")

    if suidSospechosos:
        print()
        print("[AVISO]: Binarios SUID no reconocidos: ")

        for i, binario in enumerate(suidSospechosos, 1):
            print(f"    {i}. {binario}")

        print()
        resp=input("¿Eliminar el bit SID de los binarios sospechosos? (s/N): ").strip().lower()

        if resp=="s":
            for binario in suidSospechosos:
                print(f"    Eliminando SUID de {binario}....")
                ejecutar_comando(["chmod", "u-s", binario], f"eliminar SUID de {binario}", paso)
            
            print("[CORRECTO]: Bits SUID eliminados.")
        else:
            print("[INFO]: No se han modificado los binarios SUID.")
    else:
        print("[CORRECTO]: No hay binarios SUID sospechosos.")

    print("[INFO]: Buscando binarios con bit SGID...")

    rc, salida, _ = ejecutar_comando_check(["find", "/", "-xdev", "-type", "f", "-perm", "-2000",
                                            "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"])
    
    sgidEncontrados=[l.strip() for l in salida.splitlines() if l.strip()]
    sgidSospechosos = [b for b in sgidEncontrados if b not in WHITELIST_SGID]

    print(f"    Binarios SGID encontrados:  {len(sgidEncontrados)}")
    print(f"    En whitelist:               {len(sgidEncontrados)-len(sgidSospechosos)}")
    print(f"    Sospechosos:                {len(sgidSospechosos)}")

    if sgidSospechosos:
        print()
        print("[AVISO]: Binarios SGID no reconocidos: ")

        for i, binario in enumerate(sgidSospechosos):
            print(f"    {i}. {binario}")

        print()
        resp=input("¿Eliminar el bit SID de los binarios sospechosos? (s/N): ").strip().lower()

        if resp=="s":
            for binario in sgidSospechosos:
                print(f"    Eliminando SGID de {binario}....")
                ejecutar_comando(["chmod", "g-s", binario], f"eliminar SGID de {binario}", paso)
            
            print("[CORRECTO]: Bits SUID eliminados.")
        else:
            print("[INFO]: No se han modificado los binarios SUID.")
    else:
        print("[CORRECTO]: No hay binarios SUID sospechosos.")


def paso2_auditoria_filesystem():
    print()
    print("="*100)
    print("[PASO 2]: Auditar binarios SUID/SGID.")
    print("="*100)

    print()
    print("2a: Directorios world-writable sin sticky bit.")
    print()

    paso="Paso 2"


    rc, salida, _ = ejecutar_comando_check(["find", "/", "-xdev", "-type", "d", "-perm", 
                                            "-0002", "!", "-perm", "-1000", "-not", "-path",
                                            "/proc/*", "-not", "-path", "/sys/*"])
    
    dirsSinSticky=[l.strip() for l in salida.splitlines() if l.strip()]

    if dirsSinSticky:
        print(f"[AVISO]: {len(dirsSinSticky)} directorio(s) world-writable sin sticky bit:")
        for d in dirsSinSticky:
            print(f"    - {d}")
    
        print()
        resp=input("¿Añadir sticky bit a estos directorios? (s/N): ").strip().lower()

        if resp=="s":
            for d in dirsSinSticky:
                ejecutar_comando(["chmod", "+t", d], f"añadir sticky bit a {d}", paso)
            print("[CORRECTO]: Sticky bit añadido.")
        else:
            print("[INFO]: No se han modificado los directorios.")
    else:
        print("[CORRECTO]: Todos los directorios world-writable tienen sticky bit.")

    print()
    print("2b: Ficheros sin propietario válido (huérfanos).")
    print()

    rc, salida, _=ejecutar_comando_check(["find", "/", "-xdev", "-nouser", "-o", "-nogroup", "-not", 
                                          "-path", "/proc/*", "-not", "-path", "/sys/*"])


    huerfanos=[l.strip() for l in salida.splitlines() if l.strip()]

    if huerfanos:
        maxMostrar=20
        print(f"[AVISO]: {len(huerfanos)} fichero(s) sin propietario válido:")
        for f in huerfanos[:maxMostrar]:
            print(f"    - {f}")
        if len(huerfanos)>maxMostrar:
            print(f"    ... y {len(huerfanos)-maxMostrar} más.")

        print()
        print("[INFO]: Revisa estos ficheros manualmente.")
        print("        Puedes asignarles un propietario con:")
        print("        sudo chown root:root <fichero>")
    else:
        print("[CORRECTO]: No hay ficheros sin propietario válido.")

    print()
    print("2c: Ficheros world-writable.")
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
        print(f"[AVISO]: {len(wwFicheros)} fichero(s) world-writable:")
        for f in wwFicheros[:maxMostrar]:
            print(f"    - {f}")

        if len(wwFicheros)>maxMostrar:
            print(f"    ... y {len(wwFicheros)-maxMostrar} más.")

        print()
        resp=input("¿Eliminar el permiso de escritura para 'otros' de estos ficheros? (s/N): ").strip().lower()

        if resp=="s":
            for f in wwFicheros:
                ejecutar_comando(["chmod", "o-w", f], f"eliminar world-writable de {f}", paso)
            
            print("[CORRECTO]: Permisos restringidos.")
        else:
            print("[INFO]: No se han modificado los ficheros.")
    else:
        print("[CORRECTO]: No hay ficheros world-writable fuera de directorios temporales.")


def paso3_opciones_montaje():
    print()
    print("="*100)
    print("[PASO 3]: Configurar opciones de montaje.")
    print("="*100)
    print()

    paso="Paso 3"

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
        print(f"[INFO]: Verificando opciones de montaje para {punto}...")

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
            print(f"[AVISO]: {punto} no tiene entrada en {FSTAB}.")

            if punto=="/tmp":
                print(f"[INFO]: Añadiendo entrada para {punto} en {FSTAB}...")
                opciones=",".join(["defaults"] + opcionesRequeridas)
                nuevaLinea=f"tmpfs {punto} tmpfs {opciones}  0  0"
                lineas.append(nuevaLinea)
                modificado=True
                print(f"[CORRECTO]: Entrada añadida: {nuevaLinea}")
            elif punto=="/dev/shm":
                print(f"[INFO]: Añadiendo entrada para {punto} en {FSTAB}...")
                opciones=",".join(["defaults"]+opcionesRequeridas)
                nuevaLinea=f"tmpfs {punto} tmpfs {opciones}  0  0"
                linea.append(nuevaLinea)
                modificado=True
                print(f"[CORRECTO]: Entrada añadida: {nuevaLinea}")
        else:
            campos=lineas[lineaEncontrada].split()
            opcionesActuales=campos[3].split(",")
            opcionesFaltantes=[o for o in opcionesRequeridas if o not in opcionesActuales]

            if opcionesFaltantes:
                print(f"[AVISO]: Faltan opciones: {', '.join(opcionesFaltantes)}")
                nuevasOpciones=opcionesActuales+opcionesFaltantes
                campos[3]=",".join(nuevasOpciones)
                lineas[lineaEncontrada]="\t".join(campos)
                modificado=True
                print(f"[CORRECTO]: Opciones actualizadas: {campos[3]}")
            else:
                print(f"[CORRECTO]: {punto} ya tiene {', '.join(opcionesRequeridas)}")
        
    if modificado:
        nuevoContenido="\n".join(lineas)
        if not nuevoContenido.endswith("\n"):
            nuevoContenido+="\n"
        if escribir_fichero(FSTAB, nuevoContenido, paso=paso):
            print()
            print(f"[INFO]: {FSTAB} actualizado. Remontando particiones...")
            ejecutar_comando(["mount", "-o", "remount", "/tmp"], "remontar /tmp", paso)
            ejecutar_comando(["mount", "-o", "remount", "/dev/shm"], "remontar /dev/shm", paso)
            print("[CORRECTO]: Particiones remontadas con las nuevas opciones.")
    else:
        print()
        print("[CORRECTO]: Todas las opciones de montaje están correctas.")



def paso4_chattr_ficheros():
    print()
    print("="*100)
    print("[PASO 4]: Proteger ficheros críticos.")
    print("="*100)
    print()

    paso="Paso 4"

    print("[INFO]: Estado actual de los ficheros críticos.")
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
            print(f"  \033[91m[ERROR]\033[0m    No se pudo leer: {nombre}")

    print()
    print("¿Qué deseas hacer?")
    print()
    print(" 1) Bloquear - Protege contra modificaciones")
    print(" 2) Desbloquear - Permite gestión de usuarios/grupos")
    print(" 0) Saltar este paso")
    print()

    opcion=input("Selecciona una opción [0-2]: ").strip()

    if opcion=="1":
        print()
        print("[INFO] Bloqueando ficheros críticos...")
        for fichero in FICHEROS_CRITICOS:
            nombre=os.path.basename(fichero)
            if estadoActual.get(fichero, False):
                print(f"    [CORRECTO] {nombre} ya está bloqueado.")
            else:
                ejecutar_comando(["chattr", "+i", fichero], f"bloquear {fichero}", paso)
                print(f"[CORRECTO]: {nombre} bloqueado.")

        print()
        print("[CORRECTO]: Ficheros críticos protegidos.")
        print("[INFO]: Recuerda desbloquear antes de gestionar usuarios o grupos.")
    
    elif opcion=="2":
        print()
        print("[INFO]: Desbloqueando ficheros críticos...")
        for fichero in FICHEROS_CRITICOS:
            nombre=os.path.basename(fichero)
            if not estadoActual.get(fichero, False):
                print(f"[CORRECTO]: {nombre} ya está desbloqueado.")
            else:
                ejecutar_comando(["chattr", "-i", fichero], f"desbloquear {fichero}", paso)
                print(f"[CORRECTO]: {nombre} desbloqueado.")
        print()
        print("[CORRECTO]: Ficheros desbloqueados. Ya puede gestionar usuarios y grupos.")
        print("[AVISO]: No olvide volver a bloquearlos cuando termine.")
    else:
        print("[INFO]: Paso omitido.")


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
                paso1_auditar_suid_sgid
                volver_al_menu()
            case "2":
                paso2_auditoria_filesystem
                volver_al_menu()
            case "3":
                paso3_opciones_montaje
                volver_al_menu()
            case "4":
                paso4_chattr_ficheros
                volver_al_menu()
            case "q":
                print("\n[INFO]: Saliendo del script.")
                sys.exit(0)
            case _:
                print("[ERROR]: Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()



