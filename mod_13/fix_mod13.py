#!/usr/bin/env python3

import os
import sys
import time
import glob
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, 
                   registrar_errores, 
                   comprobar_root,
                   ejecutar_comando, 
                   ejecutar_comando_check,
                   escribir_fichero, 
                   leer_fichero,
                   pedir_input_doble, 
                   cambiar_permisos,
                   volver_al_menu, 
                   print_aviso, 
                   print_correcto, 
                   print_error,
                   print_info
                   )


# =============================================================================
# CONSTANTES
# =============================================================================

LOG_FILE= "/var/log/hardening/modulo13_fix.log"

BACKUP_DIR ="/var/backups/hardening"
BACKUP_CONF="/etc/hardening/backup.conf"
GPG_KEY_FILE = "/etc/hardening/backup.key"

# Directorios/ficheros obligatorios para backup de sistema
SISTEMA_DIRS = [
    "/etc",
]



# =============================================================================
# FUNCIONES AUXILIARES
# =============================================================================

def obtener_fecha():
    """Retorna la fecha actual en formato días/mes/año_hora:minutos:segundos."""
    return time.strftime("%Y%m%d_%H%M%S")


def obtener_passphrase():
    """Lee la contraseña GPG del fichero de clave."""
    if not os.path.isfile(GPG_KEY_FILE):
        return None
    contenido =leer_fichero(GPG_KEY_FILE)
    if contenido:
        return contenido.strip()
    return None


def obtener_rutas_extra():
    """Lee las rutas extra configuradas en backup.conf."""
    if not os.path.isfile(BACKUP_CONF):
        return []
    contenido = leer_fichero(BACKUP_CONF)
    if not contenido:
        return []
    rutas=[]
    for linea in contenido.splitlines():
        limpia=linea.strip()
        if limpia and not limpia.startswith("#"):
            if os.path.exists(limpia):
                rutas.append(limpia)
    return rutas


def hacer_backup(nombre, rutas, passphrase, tipo="completo"):
    """
    Crea un backup cifrado de las rutas especificadas.

    Args:
        nombre: Nombre base del backup (sistema, usuarios, extra)
        rutas: Lista de rutas a respaldar
        passphrase: Contraseña para cifrado GPG
        tipo: "completo" o "diferencial"

    Return:
        str: Ruta del fichero de backup generado, o None si falla
    """
    fecha=obtener_fecha()
    snarFile=os.path.join(BACKUP_DIR, f"{nombre}.snar")
    tarFile=os.path.join(BACKUP_DIR, f"backup_{nombre}_{tipo}_{fecha}.tar.gz")
    gpgFile = tarFile + ".gpg"
    hashFile = gpgFile + ".sha256"

    # Para backup completo, eliminar fichero .snar anterior
    if tipo == "completo" and os.path.isfile(snarFile):
        os.remove(snarFile)

    # Para backup diferencial, copiar el .snar del completo
    # (así compara siempre contra el completo, no el diferencial anterior)
    snarOrig= os.path.join(BACKUP_DIR, f"{nombre}_completo.snar")
    if tipo == "diferencial":
        if os.path.isfile(snarOrig):
            ejecutar_comando_check(["cp", snarOrig, snarFile])
        else:
            print_aviso(f"No existe backup completo previo de '{nombre}'. Creando completo en su lugar...")
            tipo = "completo"
            if os.path.isfile(snarFile):
                os.remove(snarFile)

    # Filtrar rutas que no existen
    rutasValidas = [r for r in rutas if os.path.exists(r)]
    if not rutasValidas:
        print_aviso(f"No hay rutas válidas para '{nombre}'.")
        return None

    # Crear tar con incremental
    print_info(f"Creando {tipo} de '{nombre}'...")
    comando = ["tar", "--listed-incremental="+snarFile, "-czf",tarFile] + rutasValidas

    rc, _, stderr = ejecutar_comando_check(comando)
    if rc != 0 and rc != 1:
        # rc=1 es "files changed during archive", aceptable
        print_error(f"Error al crear tar: {stderr.strip()[:200]}")
        registrar_errores("Backup", f"Error tar {nombre}: {stderr.strip()[:200]}")
        return None

    # Guardar .snar del completo como referencia
    if tipo == "completo":
        ejecutar_comando_check(["cp", snarFile, snarOrig])

    # Cifrar con GPG
    print_info("Cifrando backup...")
    rc, _, stderr = ejecutar_comando_check(["gpg", "--batch", "--yes", "--symmetric","--cipher-algo", "AES256","--passphrase", passphrase,"--output", gpgFile, tarFile])

    if rc != 0:
        print_error(f"Error al cifrar: {stderr.strip()[:200]}")
        registrar_errores("Backup", f"Error GPG {nombre}: {stderr.strip()[:200]}")
        return None

    # Eliminar tar sin cifrar
    os.remove(tarFile)

    # Generar hash SHA-256
    try:
        sha256 = hashlib.sha256()
        with open(gpgFile, "rb") as f:
            for bloque in iter(lambda: f.read(65536), b""):
                sha256.update(bloque)
        escribir_fichero(hashFile, sha256.hexdigest() +"  " +os.path.basename(gpgFile)+ "\n", paso="Backup")
    except OSError as e:
        print_aviso(f"No se pudo generar hash: {e}")

    # Mostrar información
    tamano = os.path.getsize(gpgFile)
    if tamano > 1048576:
        tamanoStr = f"{tamano / 1048576:.1f} MB"
    else:
        tamanoStr = f"{tamano / 1024:.1f} KB"

    print_correcto(f"{os.path.basename(gpgFile)} ({tamanoStr})")

    return gpgFile


def rotar_backups(nombre, maxCompletos=4):
    """
    Elimina los backups completos más antiguos, manteniendo solo los últimos maxCompletos. 
    También elimina los diferenciales asociados a completos eliminados.

    Args:
        nombre (str): Nombre del backup
        maxCompletos (int): Números de backups completos a mantener
    """
    patron = os.path.join(BACKUP_DIR,f"backup_{nombre}_completo_*.tar.gz.gpg")
    completos = sorted(glob.glob(patron))

    if len(completos) <= maxCompletos:
        return

    eliminar = completos[:len(completos) - maxCompletos]
    for fichero in eliminar:
        os.remove(fichero)
        # Eliminar hash asociado
        hashFile = fichero + ".sha256"
        if os.path.isfile(hashFile):
            os.remove(hashFile)

    print_info(f"Rotación: eliminados {len(eliminar)} backup(s) antiguo(s) de '{nombre}'.")




def paso1_configurar():
    """
    Crea el directorio de backups con permisos restrictivos y configura la contraseña de cifrado GPG.
    """
    print()
    print("="*100)
    print("[PASO 1]: Configurar directorio de backups y cifrado")
    print("="*100)
    print()

    paso="Paso 1"

    # 1a. Crear directorio de backups 
    if not os.path.isdir(BACKUP_DIR):
        ejecutar_comando(["mkdir", "-p", BACKUP_DIR], f"crear {BACKUP_DIR}", paso)
        print_correcto(f"Directorio creado: {BACKUP_DIR}")
    else:
        print_correcto(f"Directorio ya existe: {BACKUP_DIR}")

    cambiar_permisos(BACKUP_DIR, permisos="0o700",propietario="root", grupo="root", paso=paso)
    print_correcto("Permisos 700 (solo root).")

    # 1b. Crear directorio de configuración 
    confDir = os.path.dirname(BACKUP_CONF)
    if not os.path.isdir(confDir):
        ejecutar_comando(["mkdir", "-p", confDir],f"crear {confDir}",paso)

    # ── 1c: Configurar contraseña GPG ──
    print()
    if os.path.isfile(GPG_KEY_FILE):
        print_info("Ya existe una contraseña de cifrado configurada.")
        resp = input("¿Cambiarla? (s/n): ").strip().lower()
        if resp != "s":
            print_correcto("Contraseña existente conservada.")
            return
    else:
        print_info("Se necesita una contraseña para cifrar los backups.")
        print_info("Esta contraseña es necesaria para restaurar.")
        print_info("Guárdala en un lugar seguro fuera del servidor.")
        print()

    print_info("Atención. Se recomienda una contraseña de mínimo 8 caracteres.")
    passphrase=pedir_input_doble("Contraseña de cifrado", ocultar=True)
    

    escribir_fichero(GPG_KEY_FILE, passphrase + "\n", permisos=0o600,
                     paso=paso)
    cambiar_permisos(GPG_KEY_FILE, propietario="root", grupo="root",
                     paso=paso)
    print_correcto("Contraseña de cifrado configurada.")
    print()
    print_info("Guarda esta contraseña en un lugar seguro fuera del servidor. Sin ella no podrás restaurar los backups.")
    print()



def paso2_configurar_extras():
    """
    Paso opcional para añadir rutas adicionales al backup.
    """
    print()
    print("="*100)
    print("[PASO 2]: Configurar rutas extra para backup")
    print("="*100)
    print()

    paso="Paso 2"

    # Mostrar rutas actuales
    rutasActuales = obtener_rutas_extra()
    if rutasActuales:
        print_info("Rutas extra configuradas actualmente:")
        for ruta in rutasActuales:
            print(f"  - {ruta}")
        print()

    print_info("Rutas obligatorias (siempre se respaldan):")
    print("  - /etc (configuraciones)")
    print("  - Lista de paquetes instalados")
    print("  - Crontabs")
    print("  - /home (datos de usuarios)")
    print()
    print_info("Ejemplos de rutas extra:")
    print("  - /var/www     (sitios web)")
    print("  - /opt         (aplicaciones)")
    print("  - /srv         (datos de servicios)")
    print("  - /var/lib/mysql (datos MySQL)")
    print()

    rutas = list(rutasActuales)

    while True:
        entrada = input("Ruta a añadir (dejar vacío para terminar): ").strip()

        if not entrada:
            break

        if not entrada.startswith("/"):
            print_error("La ruta debe ser absoluta (empezar por /).")
            continue

        if not os.path.exists(entrada):
            print_aviso(f"{entrada} no existe actualmente.")
            resp = input("¿Añadirla igualmente? (s/n): ").strip()
            if resp.lower() != "s":
                continue

        if entrada in rutas:
            print_info(f"{entrada} ya está en la lista.")
            continue

        rutas.append(entrada)
        print_correcto(f"Añadida: {entrada}")
        print()

    # Dar opción a eliminar alguna ruta
    if rutas:
        print()
        resp = input("¿Quieres eliminar alguna ruta? (s/n): ").strip()
        if resp.lower() == "s":
            for i, ruta in enumerate(rutas, 1):
                print(f"  {i}) {ruta}")
            while True:
                numStr = input("  Número a eliminar (vacío para terminar): ").strip()
                if not numStr:
                    break
                if numStr.isdigit() and 1 <=int(numStr) <= len(rutas):
                    eliminada = rutas.pop(int(numStr) - 1)
                    print_correcto(f"Eliminada: {eliminada}")
                else:
                    print_error("Número no válido.")

    # Guardar configuración
    contenido = "# Rutas extra para backup de hardening\n"
    contenido += "# Una ruta por línea\n"
    contenido += "#\n"
    for ruta in rutas:
        contenido += ruta + "\n"

    escribir_fichero(BACKUP_CONF, contenido, permisos=0o600,paso=paso)

    print()
    if rutas:
        print_correcto(f"{len(rutas)} ruta(s) extra configurada(s).")
    else:
        print_correcto("Sin rutas extra (solo backups obligatorios).")



def paso3_backup_manual():
    """
    Ejecuta un backup completo de los tres conjuntos:
    sistema, usuarios y extra.
    """
    print()
    print("="*100)
    print("[PASO 3]: Ejecutar backup manual (completo)")
    print("="*100)
    print()

    paso="Paso 3"

    # Verificar requisitos
    if not os.path.isdir(BACKUP_DIR):
        print_error("Directorio de backups no configurado. Ejecuta el paso 1.")
        return

    passphrase = obtener_passphrase()
    if not passphrase:
        print_error("Contraseña de cifrado no configurada. Ejecuta el paso 1.")
        return


    # 3a. Backup de sistema
    print("[1/3] Backup de sistema...")

    # Guardar lista de paquetes
    pkgFile = os.path.join(BACKUP_DIR, "paquetes_instalados.txt")
    rc, salida, _ = ejecutar_comando_check(["dpkg", "--get-selections"])
    if rc==0:
        escribir_fichero(pkgFile, salida, paso=paso)
        print_correcto("Lista de paquetes guardada.")

    # Guardar crontabs
    cronDir = os.path.join(BACKUP_DIR, "crontabs")
    if not os.path.isdir(cronDir):
        os.makedirs(cronDir, exist_ok=True)

    # Crontab de root
    rc, salida, _ = ejecutar_comando_check(["crontab", "-l"])
    if rc == 0 and salida.strip():
        escribir_fichero(os.path.join(cronDir, "root.crontab"),salida, paso=paso)

    # Copiar cron.d
    rc, _, stderr=ejecutar_comando_check(["cp", "-r", "/etc/cron.d", cronDir + "/cron.d"])
    if rc!=0:
        print_error(f"Error al copiar cron.d: {stderr.strip()[:200]}")

    rutasSistema= SISTEMA_DIRS + [pkgFile, cronDir]
    hacer_backup("sistema", rutasSistema, passphrase, "completo")

    # Limpiar temporales
    if os.path.isfile(pkgFile):
        os.remove(pkgFile)
    rc,_,stderr=ejecutar_comando_check(["rm", "-rf", cronDir])
    if rc!=0:
        print_error(f"Error al limpiar archivos temporales: {stderr.strip()[:200]}")

    print()

    #3b. Backup de usuarios
    print("[2/3] Backup de usuarios...")
    if os.path.isdir("/home"):
        hacer_backup("usuarios", ["/home"], passphrase, "completo")
    else:
        print_aviso("El directorio '/home' no existe.")
    print()

    # 3c: Backup extra
    print("[3/3] Backup extra...")
    rutasExtra = obtener_rutas_extra()
    if rutasExtra:
        hacer_backup("extra", rutasExtra, passphrase, "completo")
    else:
        print_info("Sin rutas extra configuradas (omitido).")

    # Rotación
    print()
    print_info("Rotando backups antiguos...")
    rotar_backups("sistema")
    rotar_backups("usuarios")
    rotar_backups("extra")

    print()
    print_correcto("Backup completo finalizado.")
    print_info(f"Ubicación: {BACKUP_DIR}")
    print()
    print_info("RECOMENDACIÓN: Copie el contenido de este directorio a una unidad externa "
    "(unidad USB o disco duro externo por ejemplo) para proteger los backups ante un fallo total del servidor.")
    print(f"  Ejemplo: cp -r {BACKUP_DIR} /media/<unidad_externa>/")
