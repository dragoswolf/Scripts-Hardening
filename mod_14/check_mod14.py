#!/usr/bin/env python3
#=========================================================================================================
# check_mod14.py - Script de verificación para el módulo 14 - Copias de seguridad
#=========================================================================================================
# Este script implementa las siguientes medidas de seguridad:
#
#   Paso 1: Verificar directorio de backups y cifrado GPG
#   Paso 2: Verificar que existen backups recientes
#   Paso 3: Verificar backup automático programado
#   Paso 4: Verificar integridad del último backup
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo14_check.log
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================
import os
import sys
import glob
import hashlib


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging,
                   mostrar_resumen,
                   ejecutar_comando_check,
                   leer_fichero,
                   comprobar_root,
                   contadores,
                   resultado_fail,
                   resultado_ok,
                   resultado_warn,
                   verificar_permisos,
                   verificar_antiguedad)


#=========================================================================================================
# CONSTANTES
#=========================================================================================================

LOG_FILE= "/var/log/hardening/modulo14_check.log"

BACKUP_DIR ="/var/backups/hardening"
BACKUP_CONF="/etc/hardening/backup.conf"
GPG_KEY_FILE = "/etc/hardening/backup.key"
CRON_BACKUP = "/etc/cron.d/hardening-backup"
#=========================================================================================================


def verificar_paso1():
    """
    Verifica que el directorio de backups existe con permisos correctos
    y que la contraseña de cifrado está configurada.
    """

    print()
    print("="*100)
    print("[PASO 1]: Verificar directorio de backups y cifrado")
    print("="*100)
    print()

    paso="Paso 1"

    # 1a. Comprobar la existencia del directorio de backups
    if os.path.isdir(BACKUP_DIR):
        resultado_ok(f"Directorio {BACKUP_DIR} existe")
    else:
        resultado_fail(f"Directorio {BACKUP_DIR} no existe. Ejecuta el paso 1.", paso)
        return
    
    # 1b. Comprobar permisos del directorio
    
    if verificar_permisos(BACKUP_DIR, "700", 0, 0, paso=paso):
        resultado_ok("Permisos del directorio de respaldo correctos.")
    else:
        resultado_fail("Permisos del directorio de respaldo incorrectos.", paso)

    # 1c. Contraseña de cifrado
    if os.path.isfile(GPG_KEY_FILE):
        resultado_ok("Contraseña de cifrado configurada.")
        if verificar_permisos(GPG_KEY_FILE, "600", 0,0, paso):
            resultado_ok("Permisos del fichero de cifrado correctos.")
        else:
            resultado_fail("Permisos del fichero de cifrado incorrectos.", paso)
    else:
        resultado_fail("Contraseña de cifrado no configurada. Ejecuta paso 1.", paso)


def verificar_paso2():
    """
    Verifica que existen backups de sistema y usuarios y que son recientes
    """
    print()
    print("="*100)
    print("[PASO 2]: Verificar backups existentes")
    print("="*100)
    print()

    paso="Paso 2"

    # 2a. Verificar directorio
    if not os.path.isdir(BACKUP_DIR):
        resultado_fail("Directorio de backups no existe.", paso)
        return
    
    # 2b. Verificar backups completos y diferenciales
    for nombre in ["sistema", "usuarios"]:
        completos=sorted(glob.glob(os.path.join(BACKUP_DIR, f"backup_{nombre}_completo_*.tar.gz.gpg")))

        if completos:
            ultimo=completos[-1]
            dias=verificar_antiguedad(ultimo, f"Backup {nombre} completo", mostrarTamano=True)
            
            if dias is not None and dias > 35:
                resultado_warn(f"Backup {nombre} tiene {int(dias)} días. El completo podría no estar ejecutándose.")
        else:
            resultado_fail(f"No hay backup completo de '{nombre}'. EJecuta el paso 3.", paso)

        # Buscar diferenciales
        diferenciales=sorted(glob.glob(os.path.join(BACKUP_DIR, f"backup_{nombre}_diferencial_*.tar.gz.gpg")))

        if diferenciales:
            ultimo_dif=diferenciales[-1]
            dias = verificar_antiguedad(ultimo_dif, f"Backup {nombre} diferencial.")
            if dias is not None and dias >8:
                resultado_warn(f"Diferencial de {nombre} tiene {int(dias)} días.")
        else:
            resultado_warn(f"Sin backup diferencial de '{nombre}'. Se creará en el próximo domingo.")
        

    # 2c. Verificar extras si están configurados
    if os.path.isfile(BACKUP_CONF):
        contenido=leer_fichero(BACKUP_CONF)
        if contenido:
            rutasExtra=[l.strip() for l in contenido.splitlines() if l.strip() and not l.strip().startswith("#")]
            if rutasExtra:
                completos_ext=glob.glob(os.path.join(BACKUP_DIR, "backup_extra_completo_*.tar.gz.gpg"))
                if completos_ext:
                    resultado_ok("Backup extra existe.")
                else:
                    resultado_warn("Rutas extra configuradas pero sin backup.")



def verificar_paso3():
    """
    Verifica que el cron de backup está configurado y que el servicio cron está activo.
    """
    print()
    print("="*100)
    print("[PASO 3]: Verificar backup automatico programado.")
    print("="*100)
    print()

    paso="Paso 3"

    # 3a. Comprobar existencia del fichero cron
    if os.path.isfile(CRON_BACKUP):
        resultado_ok(f"Cron de backup configurado ({CRON_BACKUP}).")
    else:
        resultado_fail("Backup automático no programado. Ejecuta el paso 4.", paso)
    
    # 3b. Script de backup existe
    scriptDir=os.path.dirname(os.path.abspath(__file__))
    cronScript=os.path.join(scriptDir, "backup_cron.sh")
    if os.path.isfile(cronScript):
        resultado_ok("Script de backup existe")
        if os.access(cronScript, os.X_OK):
            resultado_ok("Script tiene permisos de ejecución.")
        else:
            resultado_fail("Script no tiene permisos de ejecución.", paso)
    else:
        resultado_fail("Script de backup no existe.", paso)

    
    # 3c. Comprobar que el servicio cron existe
    rc,_,_=ejecutar_comando_check(["systemctl", "is-active", "--quiet", "cron"])
    if rc == 0:
        resultado_ok("Servicio cron activo.")
    else:
        resultado_fail("Servicio cron no activo.", paso)


def verificar_paso4():
    """
    Verifica el hash SHA-256 de los últimos backups
    """
    print()
    print("="*100)
    print("[PASO 4]: Verificar integridad del último backup.")
    print("="*100)
    print()

    paso="Paso 4"

    # 4a. Verificar directorio
    if not os.path.isdir(BACKUP_DIR):
        resultado_fail("Directorio de backups no existe", paso)
        return
    
    verificados=0
    errores =0

    # 4b. Verificar hash SHA-256 de cada backup
    for nombre in ["sistema", "usuarios", "extra"]:
        # buscar último backup
        todos=sorted(glob.glob(os.path.join(BACKUP_DIR, f"backup_{nombre}_*.tar.gz.gpg")))

        if not todos:
            continue

        ultimo=todos[-1]
        hashFile=ultimo +".sha256"
        nombreCorto=os.path.basename(ultimo)

        if not os.path.isfile(hashFile):
            resultado_warn(f"{nombreCorto}: sin ficheros de hash.")
            continue

        hashGuardado=leer_fichero(hashFile)
        if not hashGuardado:
            resultado_warn(f"{nombreCorto}: fichero de hash vacío.")
            continue

        hashGuardado=hashGuardado.strip().split()[0]

        try:
            sha256=hashlib.sha256()
            with open(ultimo, "rb") as f:
                for bloque in iter(lambda: f.read(65536), b""):
                    sha256.update(bloque)
            hashCalculado=sha256.hexdigest()

            if hashCalculado == hashGuardado:
                resultado_ok(f"{nombreCorto}: integridad correcta.")
                verificados+=1
            else:
                resultado_fail(f"{nombreCorto}: hash no coinciden. Posible corrupción.", paso)
                errores+=1
        except OSError as e:
            resultado_fail(f"{nombreCorto}: error al leer: {e}", paso)
            errores+=1

    
    # 4c. Resumen
    if verificados==0 and errores == 0:
        resultado_warn("No hay backups para verificar")


def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    print()
    print("="*100)
    print("[AUDITORÍA MÓDULO 14]: COPIAS DE SEGURIDAD")
    print("="*100)
    print()

    print()
    print("     Comprobando configuraciones de los pasos 1 al 4...")
    print()

    verificar_paso1()
    verificar_paso2()
    verificar_paso3()
    verificar_paso4()


    mostrar_resumen("fix_mod14.py")

    if contadores["checksFail"]>0:
        sys.exit(1)
    else:
        sys.exit(0)

# =============================================================================
if __name__ == "__main__":
    main()


