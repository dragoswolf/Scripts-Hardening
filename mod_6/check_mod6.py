#!/usr/bin/env python3


import os
import sys
import stat

sys.path.inser(0, os.path.join(os.path.dirname(__file__), ".."))
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
]


def verificar_paso1():
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


    if suidSospechosos:
        resultado_fail(f"{len(suidSospechosos)} binario(s) SUID fuera de whitelist: "
                       f"{', '.join(suidSospechosos)}")
    else:
        resultado_ok(f"Todos los binarios SUID ({len(suidEncontrados)}) están en la whitelist.")

    print("[INFO]: Buscando binarios con bit SGID...")

    rc, salida, _ = ejecutar_comando_check(["find", "/", "-xdev", "-type", "d", "-perm", "-2000",
                                            "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"])
    
    sgidEncontrados=[l.strip() for l in salida.splitlines() if l.strip()]
    sgidSospechosos = [b for b in sgidEncontrados if b not in WHITELIST_SGID]

    if sgidSospechosos:
        resultado_fail(f"{len(sgidSospechosos)} binario(s) SGID fuera de whitelist: "
                       f"{', '.join(sgidSospechosos)}")
        
    else:
        resultado_ok(f"Todos los binarios SGID ({len(sgidEncontrados)}) están en la whitelist.")