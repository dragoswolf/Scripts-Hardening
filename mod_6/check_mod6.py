#!/usr/bin/env python3


import os
import sys
import stat

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, comprobar_root, resultado_fail, resultado_ok,
                   resultado_warn, mostrar_resumen, contadores, volver_al_menu, ejecutar_comando_check)


LOG_FILE="/var/log/hardening/modulo6_check.log"

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
    "/etc/fstab",
]


def verificar_paso1():
    print()
    print("="*100)
    print("[PASO 1]: Auditar binarios SUID/SGID.")
    print("="*100)
    print()

    paso="Paso 1"

    print("[INFO]: Buscando binarios con bit SUID...")

    rc, salida, _ = ejecutar_comando_check(["find", "/", "-xdev", "-type", "f", "-perm", "4000",
                                            "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"])
    
    suidEncontrados=[l.strip() for l in salida.splitlines() if l.strip()]
    suidSospechosos = [b for b in suidEncontrados if b not in WHITELIST_SUID]


    if suidSospechosos:
        resultado_fail(f"{len(suidSospechosos)} binario(s) SUID fuera de whitelist: "
                       f"{', '.join(suidSospechosos[:5])}"
                       +(f" (y {len(suidSospechosos)-5} más)"
                         if len(suidSospechosos)>5 else ""), paso)
    else:
        resultado_ok(f"Todos los binarios SUID ({len(suidEncontrados)}) están en la whitelist.")

    print("[INFO]: Buscando binarios con bit SGID...")

    rc, salida, _ = ejecutar_comando_check(["find", "/", "-xdev", "-type", "f", "-perm", "-2000",
                                            "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"])
    
    sgidEncontrados=[l.strip() for l in salida.splitlines() if l.strip()]
    sgidSospechosos = [b for b in sgidEncontrados if b not in WHITELIST_SGID]

    if sgidSospechosos:
        resultado_fail(f"{len(sgidSospechosos)} binario(s) SGID fuera de whitelist: "
                       f"{', '.join(sgidSospechosos[:5])}"
                       +(f" (y {len(sgidSospechosos)-5} más)"
                         if len(sgidSospechosos)> 5 else ""), paso)
        
    else:
        resultado_ok(f"Todos los binarios SGID ({len(sgidEncontrados)}) están en la whitelist.")

def verificar_paso2():
    print()
    print("="*100)
    print("[PASO 2]: Auditoría del filesystem.")
    print("="*100)
    print()

    paso="Paso 2"

    rc, salida, _ = ejecutar_comando_check(["find", "/", "-xdev", "-type", "d", "-perm", 
                                        "-0002", "!", "-perm", "-1000", "-not",
                                        "-path", "/proc/*", "-not", "-path", "/sys/*"])
    
    dirsSinSticky=[l.strip() for l in salida.splitlines() if l.strip()]

    if dirsSinSticky:
        resultado_fail(f"{len(dirsSinSticky)} directorio(s) world-writable sin sticky bit:"
                       f"{', '.join(dirsSinSticky[:3])}"
                       +(f" (y {len(dirsSinSticky) - 3} más)"
                         if len(dirsSinSticky)>3 else ""),
                        paso)
    else:
        resultado_ok("Todos los directorios world-writable tienen sticky bit.")

    rc, salida, _=ejecutar_comando_check(["find", "/", "-xdev", "-nouser", "-o", "-nogroup",
                                          "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"])
    
    huerfanos=[l.strip() for l in salida.splitlines() if l.strip()]

    if huerfanos:
        resultado_warn(f"{len(huerfanos)} fichero(s) sin propietario válido (revisar manualmente).")
    else:
        resultado_ok("No hay ficheros sin propietario válido.")

        rc, salida, _ =ejecutar_comando_check(["find", "/", "-xdev", "-type", "f", "-perm", "-0002",
                                               "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"])
    
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
        resultado_fail(f"{len(wwFicheros)} fichero(s) world-writable:"
                       f"{', '.join(wwFicheros[:3])}"
                       +(f" (y {len(wwFicheros)-3} más)"
                         if len(wwFicheros) > 3 else ""), paso)
        
    else:
        resultado_ok("No hay ficheros world-writable fuera de directorios temporales.")


def verificar_paso3():
    print()
    print("="*100)
    print("[PASO 3]: Verificar opciones de montaje.")
    print("="*100)
    print()

    paso="Paso 3"

    montajes={
    "/tmp": ["nodev", "nosuid", "noexec"],
    "/dev/shm": ["nodev", "nosuid", "noexec"],
    }
    
    for punto, opcionesRequeridas in montajes.items():
        rc, salida, _ = ejecutar_comando_check(["findmnt", "-n", "-o", "OPTIONS", punto])

        if rc!=0 or not salida.strip():
            resultado_warn(f"{punto} no está montado como punto de montaje separado.")
            continue

        opcionesActuales=salida.strip().split(",")
        opcionesFaltantes=[o for o in opcionesRequeridas if o not in opcionesActuales]

        if opcionesFaltantes:
            resultado_fail(f"{punto}: faltan opciones "
                           f"{', '.join(opcionesFaltantes)}", paso)
        else:
            resultado_ok(f"{punto} tiene "
                         f"{', '.join(opcionesRequeridas)}")
            

def verificar_paso4():
    print()
    print("="*100)
    print("[PASO 4]: Verificar protección en ficheros críticos.")
    print("="*100)
    print()

    paso="Paso 4"

    for fichero in FICHEROS_CRITICOS:
        nombre=os.path.basename(fichero)

        if not os.path.isfile(fichero):
            resultado_fail(f"{nombre} no existe.", paso)
            continue

        rc, salida, _=ejecutar_comando_check(["lsattr", fichero])

        if rc!=0:
            resultado_warn(f"No se pudo leer atributos de {nombre}")
            continue

        atributos=salida.split()[0] if salida.strip() else ""

        if "i" in atributos:
            resultado_ok(f"{nombre} tiene atributo inmutable.")
        else:
            resultado_fail(f"{nombre} no tiene atributo inmutable", paso)

def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    print()
    print("="*100)
    print("[AUDITORÍA MÓDULO 6]: Filesystem.")
    print("="*100)
    print()

    print()
    print("     Comprobando configuraciones de los pasos 1 al 4...")
    print()

    verificar_paso1()
    verificar_paso2()
    verificar_paso3()
    verificar_paso4()




    mostrar_resumen("fix_mod6.py")

    if contadores["checksFail"]>0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__=="__main__":
    main()


    