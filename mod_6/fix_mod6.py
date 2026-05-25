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



def paso1_auditar_suid_sgid():
    print()
    print("="*100)
    print("[PASO 1]: Auditar binarios SUID/SGID.")
    print("="*100)
    print()

    paso="Paso 1"

    print("[INFO]: Buscando binarios con bit SUID...")

    rc, salida, _ = ejecutar_comando_check(["find", "/", "-xdev", "-type", "d", "-perm", "4000",
                                            "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"])
    
    suidEncontrados=[l.strip() for l in salida.splitlines() if l.strip()]
    suidSospechosos = [b for b in suidEncontrados if b not in WHITELIST_SUID]

    print(f"    Binarios SUID encontrados:  {len(suidEncontrados)}")
    print(f"    En whitelist:               {len(suidEncontrados)-len(suidSospechosos)}")
    print(f"    Sospechosos:                {len(suidSospechosos)}")

    if suidSospechosos:
        print()
        print("[AVISO]: Binarios SUID no reconocidos: ")

        for i, binario in enumerate(suidSospechosos):
            print(f"    {i}. {binario}")

        print()
        resp=input("¿Eliminar el bit SID de los binarios sospechosos? (s/N): ").strip().lower()

        if resp=="s":
            for binario in suidSospechosos:
                print(f"    Eliminando SUID de {binario}....")
                ejecutar_comando(["chmod", "u+s", binario], f"eliminar SUID de {binario}", paso)
            
            print("[CORRECTO]: Bits SUID eliminados.")
        else:
            print("[INFO]: No se han modificado los binarios SUID.")
    else:
        print("[CORRECTO]: No hay binarios SUID sospechosos.")

    print("[INFO]: Buscando binarios con bit SGID...")

    rc, salida, _ = ejecutar_comando_check(["find", "/", "-xdev", "-type", "d", "-perm", "-2000",
                                            "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"])
    
    sgidEncontrados=[l.strip() for l in salida.splitlines() if l.strip()]
    sgidSospechosos = [b for b in sgidEncontrados if b not in WHITELIST_SUID]

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
                ejecutar_comando(["chmod", "u+s", binario], f"eliminar SGID de {binario}", paso)
            
            print("[CORRECTO]: Bits SUID eliminados.")
        else:
            print("[INFO]: No se han modificado los binarios SUID.")
    else:
        print("[CORRECTO]: No hay binarios SUID sospechosos.")
