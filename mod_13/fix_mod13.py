#!/usr/bin/env python3
#=========================================================================================================
# fix_mod13.py - Script de fortificación para el módulo 13 - Copias de seguridad
#=========================================================================================================
# Este script implementa las siguientes medidas de seguridad:
#
#   Paso 1: Verificar que rsyslog está instalado y activo
#   Paso 2: Configurar persistencia de journald
#   Paso 3: Asegurar permisos de ficheros de log
#   Paso 4: Configurar logrotate
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo13_fix.log
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================


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


#=========================================================================================================
# CONSTANTES
#=========================================================================================================

LOG_FILE= "/var/log/hardening/modulo13_fix.log"

BACKUP_DIR ="/var/backups/hardening"
BACKUP_CONF="/etc/hardening/backup.conf"
GPG_KEY_FILE = "/etc/hardening/backup.key"
CRON_BACKUP = "/etc/cron.d/hardening-backup"

# Directorios/ficheros obligatorios para backup de sistema
SISTEMA_DIRS = [
    "/etc",
]

CRON_BACKUP_TARGETS = f"""#!/bin/bash
# #=========================================================================================================
# backup_cron.sh — Backup automático de hardening
# #=========================================================================================================
# Uso: backup_cron.sh [completo|diferencial]
#
# Autor: Dragos George Stan
# TFG: Implementación Integral de Hardening en Ubuntu Server para PYMEs
#=========================================================================================================

TIPO="${{1:-diferencial}}"
BACKUP_DIR="{BACKUP_DIR}"
GPG_KEY="{GPG_KEY_FILE}"
BACKUP_CONF="{BACKUP_CONF}"
LOG="/var/log/hardening/backup_cron.log"
FECHA=$(date '+%Y-%m-%d %H:%M:%S')

echo "=========================================================================================================" >> "$LOG"
echo "Backup $TIPO: $FECHA" >> "$LOG"
echo "=========================================================================================================" >> "$LOG"

PASSPHRASE=$(cat "$GPG_KEY")
SNAR_DIR="$BACKUP_DIR"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

backup_set() {{
    local NOMBRE="$1"
    shift
    local RUTAS=("$@")
    local SNAR="$SNAR_DIR/$NOMBRE.snar"
    local SNAR_ORIG="$SNAR_DIR/${{NOMBRE}}_completo.snar"
    local TAR="$BACKUP_DIR/backup_${{NOMBRE}}_${{TIPO}}_${{TIMESTAMP}}.tar.gz"
    local GPG="$TAR.gpg"

    if [ "$TIPO" = "completo" ]; then
        rm -f "$SNAR"
    elif [ "$TIPO" = "diferencial" ]; then
        if [ -f "$SNAR_ORIG" ]; then
            cp "$SNAR_ORIG" "$SNAR"
        else
            echo "[AVISO]: No hay backup completo previo de $NOMBRE, haciendo completo" >> "$LOG"
            rm -f "$SNAR"
        fi
    fi

    tar --listed-incremental="$SNAR" -czf "$TAR" "${{RUTAS[@]}}" 2>/dev/null

    if [ "$TIPO" = "completo" ]; then
        cp "$SNAR" "$SNAR_ORIG" 2>/dev/null
    fi

    gpg --batch --yes --symmetric --cipher-algo AES256 --passphrase "$PASSPHRASE" --output "$GPG" "$TAR" 2>/dev/null

    rm -f "$TAR"

    sha256sum "$GPG" > "$GPG.sha256" 2>/dev/null

    echo "[CORRECTO]: $NOMBRE ($TIPO): $(du -h "$GPG" | cut -f1)" >> "$LOG"
}}

# Backup de sistema
PKGFILE="$BACKUP_DIR/paquetes_instalados.txt"
dpkg --get-selections > "$PKGFILE" 2>/dev/null
CRONDIR="$BACKUP_DIR/crontabs_tmp"
mkdir -p "$CRONDIR"
crontab -l > "$CRONDIR/root.crontab" 2>/dev/null
cp -r /etc/cron.d "$CRONDIR/cron.d" 2>/dev/null

backup_set "sistema" /etc "$PKGFILE" "$CRONDIR"

rm -f "$PKGFILE"
rm -rf "$CRONDIR"

# Backup de usuarios
if [ -d /home ]; then
    backup_set "usuarios" /home
fi

# Backup extra (si hay configuración)
if [ -f "$BACKUP_CONF" ]; then
    EXTRA_RUTAS=()
    while IFS= read -r linea; do
        linea=$(echo "$linea" | xargs)
        [[ -z "$linea" || "$linea" == \\#* ]] && continue
        [ -e "$linea" ] && EXTRA_RUTAS+=("$linea")
    done < "$BACKUP_CONF"

    if [ ${{#EXTRA_RUTAS[@]}} -gt 0 ]; then
        backup_set "extra" "${{EXTRA_RUTAS[@]}}"
    fi
fi

# Rotación (mantener últimos 4 completos)
for NOMBRE in sistema usuarios extra; do
    COMPLETOS=($(ls -1t "$BACKUP_DIR"/backup_${{NOMBRE}}_completo_*.tar.gz.gpg 2>/dev/null))
    if [ ${{#COMPLETOS[@]}} -gt 4 ]; then
        for ((i=4; i<${{#COMPLETOS[@]}}; i++)); do
            rm -f "${{COMPLETOS[$i]}}" "${{COMPLETOS[$i]}}.sha256"
        done
        echo "[INFO]: Rotados backups antiguos de $NOMBRE" >> "$LOG"
    fi
done

echo "" >> "$LOG"
"""


CRON_CONTENIDO = """
#=========================================================================================================
# Backup automático de hardening
# Completo: día 1 de cada mes a las 02:00
# Diferencial: todos los domingos a las 02:00
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================

SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Backup completo mensual (día 1)
0 2 1 * * root {script_dir}/backup_cron.sh completo

# Backup diferencial semanal (domingos, excepto día 1)
0 2 * * 0 root [ $(date +\\%d) -ne 01 ] && {script_dir}/backup_cron.sh diferencial
"""

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


def restaurar_backup(nombre, passphrase):
    """Restaura el último backup completo + último backup diferencial.
    
    Args:
        nombre (str): Nombre del fichero que restaurar
        passphrase (str): Contraseña GPG para descfirar los backups

    Returns:
        True si se restauró correctamente, False en caso de error.
    """
    # Buscar último completo
    completos=sorted(glob.glob(
    os.path.join(BACKUP_DIR, f"backup_{nombre}_completo_*.tar.gz.gpg")
    ))
    if not completos:
        print_aviso(f"No hay backup completo de '{nombre}'.")
        return False

    ultimo_completo=completos[-1]
    print_info(f"Restaurando completo: {os.path.basename(ultimo_completo)}")

    # Descifrar
    tarFile = ultimo_completo.replace(".gpg", "")
    rc, _, stderr = ejecutar_comando_check(["gpg", "--batch", "--quiet", "--decrypt", "--passphrase", passphrase,"--output", tarFile, ultimo_completo])

    if rc != 0:
        print_error(f"Fallo al descifrar: {stderr.strip()[:200]}")
        return False

    # Extraer
    rc, _, stderr = ejecutar_comando_check(["tar", "--listed-incremental=/dev/null", "--overwrite", "-xzf",tarFile, "-C", "/"])
    os.remove(tarFile)

    if rc != 0:
        print_error(f"Fallo al extraer: {stderr.strip()[:200]}")
        return False

    print_correcto("Completo restaurado.")

    # Buscar último diferencial
    diferenciales = sorted(glob.glob(os.path.join(BACKUP_DIR, f"backup_{nombre}_diferencial_*.tar.gz.gpg")))

    if diferenciales:
        ultimo_dif=diferenciales[-1]
        # Verificar que es posterior al completo (crítico)
        if ultimo_dif>ultimo_completo:
            print_info(f"Aplicando diferencial: {os.path.basename(ultimo_dif)}")
            tarFile= ultimo_dif.replace(".gpg","")
            rc,_,_= ejecutar_comando_check(["gpg", "--batch", "--quiet", "--decrypt","--passphrase", passphrase,"--output", tarFile, ultimo_dif])
            if rc== 0:
                rc, _,stderr=ejecutar_comando_check(["tar", "--listed-incremental=/dev/null", "--overwrite","-xzf", tarFile, "-C", "/"])
                if rc==0:
                    os.remove(tarFile)
                    print_correcto("Diferencial aplicado.")
                else:
                    print_error(f"Fallo al aplicar el diferencial: {stderr.strip()[:200]}")
            else:
                print_aviso("No se pudo descifrar el diferencial.")
    return True


def verificar_gpg(paso="General"):
    """
    Verifica que GPG está instalado y lo instala si no lo está

    Args:
        paso (str): Paso concreto en el que se ejecuta esta función
    Return:
        bool: True si GPG está disponible, False si no se pudo instalar
    """

    rc,_,_=ejecutar_comando_check(["which", "gpg"])
    if rc==0:
        print_correcto["GPG ya está instalado."]
        return True
    
    print_info("GPG no está instalado. Instalando gnupg...")
    ejecutar_comando(["apt", "install", "-y", "gnupg"], "instalando gnupg", paso, mostrarSalida=True)
    if rc==0:
        print_correcto("GPG instalado correctamente.")
        return True
    else:
        print_error("No se pudo instalar GPG")
        registrar_errores(paso, "No se pudo instalar gnupg")
        return False



def paso1_configurar():
    """
    Crea el directorio de backups con permisos restrictivos y configura la contraseña de cifrado GPG.
    """
    print()
    print("="*100)
    print("[PASO 1]: Configurar directorio de backups y cifrado")
    print("="*100)
    print_info("Crea el directorio de backups con permisos restrictivos y configura la contraseña\n" \
    "       de cifrado GPG.")
    print()

    paso="Paso 1"

    # 1a. Verificar/Instalar GPG

    # 1b. Crear directorio de backups 
    if not os.path.isdir(BACKUP_DIR):
        ejecutar_comando(["mkdir", "-p", BACKUP_DIR], f"crear {BACKUP_DIR}", paso)
        print_correcto(f"Directorio creado: {BACKUP_DIR}")
    else:
        print_correcto(f"Directorio ya existe: {BACKUP_DIR}")

    # 1c. Asegurar permisos
    cambiar_permisos(BACKUP_DIR, permisos=0o700,propietario=0, grupo=0, paso=paso)
    print_correcto("Permisos 700 (solo root).")

    # 1d. Crear directorio de configuración 
    confDir = os.path.dirname(BACKUP_CONF)
    if not os.path.isdir(confDir):
        ejecutar_comando(["mkdir", "-p", confDir],f"crear {confDir}",paso)

    # 1e. Configurar clave GPG
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
    
    #1f.Guardar clave GPG
    escribir_fichero(GPG_KEY_FILE, passphrase + "\n", permisos=0o600, paso=paso)
    cambiar_permisos(GPG_KEY_FILE, propietario=0, grupo=0, paso=paso)
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
    print_info("Paso opcional para añadir rutas adicionales a las copias de seguridad.")
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
    print_info("Ejecuta un backup completo de los tres conjuntos: sistema, usuarios y extra.")
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
    print_info(f"  Ejemplo: cp -r {BACKUP_DIR} /media/<unidad_externa>/")


def paso4_programar_cron():
    """
    Crea el script de backup para cron y la entrada en cron.d.
    Completo mensual (día 1) + diferencial semanal (domingos).
    """
    print()
    print("="*100)
    print("[PASO 4]: Programar backup automático")
    print("="*100)
    print_info("Crea el script de backup para cron y la entrada en cron.d.\n" \
    "       Se crea backup completo mensual (día 1 de cada mes) y\n" \
    "       un diferencial semanal (domingos). Todos los backups se realizan\n" \
    "       a las 02:00.")
    print()

    paso="Paso 4"

    # 4a.Verificar contraseña de cifrado
    if not os.path.isfile(GPG_KEY_FILE):
        print_error("Contraseña de cifrado no configurada. Ejecuta el paso 1.")
        return

    scriptDir=os.path.dirname(os.path.abspath(__file__))

    # 4b. Crear script de cron
    cronScript= os.path.join(scriptDir, "backup_cron.sh")


    if escribir_fichero(cronScript, CRON_BACKUP_TARGETS, permisos=0o700, paso=paso):
        print(f"Script de backup creado: {cronScript}")
    else:
        print_error("No se ha podido crear el script")

    # 4c. Crear entrada cron
    cronContenido=CRON_CONTENIDO.replace("{script_dir}", scriptDir)
    escribir_fichero(CRON_BACKUP, cronContenido, permisos=0o644, paso=paso)
    print_correcto(f"Cron configurado: {CRON_BACKUP}")

    # 4d. Verificar cron activo
    rc, _,_= ejecutar_comando_check(["systemctl", "is-active", "--quiet","cron"])
    if rc==0:
        print_correcto("Servicio cron activo.")
    else:
        ejecutar_comando(["systemctl", "enable", "--now", "cron"], "activar cron", paso)

    print()
    print_info("Programación:")
    print("  - Completo: día 1 de cada mes a las 02:00")
    print("  - Diferencial: todos los domingos a las 02:00")
    print("  - Rotación: se conservan los últimos 4 completos")


def paso5_verificar_integridad():
    """
    Verifica la integridad de los backups existentes comprobando los hashes SHA-256 
    y realizando un test de descifrado.
    """
    print()
    print("="*100)
    print("[PASO 5]: Verificar integridad de backups")
    print("="*100)
    print_info("Verifica la integridad de los backups existentes comprobando los hashes SHA-256 y\n" \
    "       realizando un test de descifrado.")
    print()

    paso="Paso 5"

    # 5a. verificar requisitos
    if not os.path.isdir(BACKUP_DIR):
        print_error("Directorio de backups no existe.")
        return

    passphrase=obtener_passphrase()
    if not passphrase:
        print_error("Contraseña de cifrado no configurada.")
        return

    # 5b. Buscar todos los backups
    backups =sorted(glob.glob(os.path.join(BACKUP_DIR,"backup_*.tar.gz.gpg")))

    if not backups:
        print_info("No hay backups para verificar.")
        return

    errores=0
    # 5c. Verificar cada backup (hash + descifrado)
    for gpgFile in backups:
        nombre= os.path.basename(gpgFile)
        hashFile = gpgFile+".sha256"

        print_info(f"Verificando: {nombre}")

        # Verificar hash SHA-256 
        if os.path.isfile(hashFile):
            hashGuardado= leer_fichero(hashFile)
            if hashGuardado:
                hashGuardado=hashGuardado.strip().split()[0]
                sha256=hashlib.sha256()
                try:
                    with open(gpgFile, "rb") as f:
                        #Cargar en RAM los ficheros de 64 en 64 KB, para ahorrar cuello de botella
                        for bloque in iter(lambda: f.read(65536), b""):
                            sha256.update(bloque)
                    hashCalculado =sha256.hexdigest()

                    if hashCalculado == hashGuardado:
                        print_correcto("Hash SHA-256 correcto")
                    else:
                        print_error("Hash no coincide")
                        errores +=1
                        continue
                except OSError as e:
                    print_error(f"No se pudo leer: {e}")
                    errores +=1
                    continue
        else:
            print_aviso("Sin fichero de hash")

        # Test de descifrado
        rc, _, stderr = ejecutar_comando_check(["gpg", "--batch", "--quiet", "--decrypt","--passphrase", passphrase,"--output", "/dev/null", gpgFile])
        if rc==0:
            print_correcto("Descifrado correcto")
        else:
            print_error(f"Fallo al descifrar: {stderr.strip()[:200]}")
            errores +=1

    print()
    if errores==0:
        print_correcto(f"{len(backups)} backup(s) verificado(s) correctamente.")
    else:
        print_aviso(f"{errores} backup(s) con errores de {len(backups)} verificado(s).")


def paso6_restaurar():
    """
    Restaura backups de forma interactiva.
    Sistema:            obligatorio. 
    Usuarios y extra:   opcionales.
    """
    print()
    print("="*100)
    print("[PASO 6]: Restaurar backups")
    print("="*100)
    print_info("Restaura backups de forma interactiva.\n" \
    "       Sistema:           Obligatorio\n" \
    "       Usuarios y extra:  Opcionales")
    print()

    paso="Paso 6"

    # 6a. Verificar requisitos
    if not os.path.isdir(BACKUP_DIR):
        print_error("Directorio de backups no existe.")
        print()
        resp=input("¿Restaurar desde un dispositivo externo? (s/n): ").strip()
        if resp.lower()!="s":
            print_info("Restauración cancelada.")
            return
        
        #Mostrar dispositivos disponibles
        print()
        print_info("Dispositivos detectados:")
        print()

        rc, salida,_=ejecutar_comando_check(["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,LABEL", "-p"])
        if rc==0:
            for linea in salida.splitlines():
                print(f"    {linea}")
            print()
        
        dispositivo=input("Dispositivo a montar (ej: /dev/sdb1): ").strip()
        if not dispositivo:
            print_error("No se especificó dispositivo.")
            return

        # Montar dispositivo
        puntoMontaje="/mnt/backup_externo"
        os.makedirs(puntoMontaje, exist_ok=True)

        rc,_,stderr=ejecutar_comando_check(["mount", dispositivo, puntoMontaje])
        if rc!=0:
            print_error(f"No se pudo montar {dispositivo}: {stderr.strip()}")
            return
        
        print_correcto(f"Dispositivo montado en {puntoMontaje}")

        # Preguntar nombre carpeta donde están los backups dentro de la unidad externa
        print()
        carpeta=input("Carpeta de backups en el dispositivo externo (dejar vacío para 'hardening'): ").strip()
        if not carpeta:
            carpeta="hardening"

        rutaUSB=os.path.join(puntoMontaje, carpeta)
        if not os.path.isdir(rutaUSB):
            #Busca ficheros en la carpeta indicada
            backupsEnRaiz=glob.glob(os.path.join(puntoMontaje, "backup_*.tar.gz.gpg"))
            if backupsEnRaiz:
                rutaUSB=puntoMontaje
            else:
                print_error(f"No se encontraron backups en '{carpeta}' ni en la raíz del dispositivo externo.")
                return
        
        #Copiar backups al directorio local
        print_info(f"Copiando backups desde {rutaUSB}...")
        os.makedirs(BACKUP_DIR, exist_ok=True)
        rc,_, stderr=ejecutar_comando_check(["cp", "-r"] + glob.glob(os.path.join(rutaUSB, "*")) +[BACKUP_DIR])
        if rc!=0:
            print_error(f"Error al copiar: {stderr.strip()}")
            return
        
        if cambiar_permisos(BACKUP_DIR, permisos=0o700, propietario=0, grupo=0, paso=paso) and rc==0:
            print_correcto(f"Backups copiados a {BACKUP_DIR}")
            print_info(f"El dispositivo sigue montado. Si desea desmontarlo use 'sudo umount {puntoMontaje}'.")

    if not verificar_gpg(paso):
        return
           
    passphrase = obtener_passphrase()
    if not passphrase:
        passphrase = input("Contraseña de descifrado: ").strip()
        if not passphrase:
            print_error("Se necesita contraseña para restaurar.")
            return

    print_aviso("La restauración sobreescribirá ficheros existentes.")
    print_aviso("Asegúrate de que estás en un sistema recién instalado o que sabes lo que estás haciendo. ")
    print()
    resp=input("¿Continuar con la restauración? (s/n): ").strip()
    if resp.lower() != "s":
        print_info("Restauración cancelada.")
        return


    # 6b. Restaurar sistema (obligatorio)
    print()
    print("[1/3] Restaurando backup de sistema...")
    if restaurar_backup("sistema", passphrase):
        # Restaurar paquetes si existe la lista
        pkgFile= "/var/backups/hardening/paquetes_instalados.txt"
        if os.path.isfile(pkgFile):
            print()
            resp = input("¿Restaurar paquetes instalados? (s/n): ").strip()
            if resp.lower()=="s":
                print_info("Restaurando paquetes...")
                rc1,_,_=ejecutar_comando_check(["bash", "-c", f"dpkg --set-selections < {pkgFile}"])
                rc2,_,_=ejecutar_comando_check(["apt-get", "dselect-upgrade", "-y"])
                if rc1!=0 or rc2 !=0:
                    print_error("Error al restaurar paquetes.")
                    registrar_errores(paso, "Error al restaurar paquetes")
                print("Paquetes restaurados.")
    print()

    # 6c. Restaurar usuarios (opcional)
    print("[2/3] Backup de usuarios (/home)...")
    completos_usr = glob.glob(os.path.join(BACKUP_DIR,"backup_usuarios_completo_*.tar.gz.gpg"))
    if completos_usr:
        resp = input("¿Restaurar datos de usuarios? (s/n): ").strip()
        if resp.lower()=="s":
            if restaurar_backup("usuarios", passphrase):
                print_correcto("Backup de datos de usuarios restaurada.")
            else:
                print_error("Error al restaurar backup de datos de usuarios.")
                registrar_errores(paso, "Error al restaurar backup de datos de usuarios.")
        else:
            print_info("Backup de usuarios omitido.")
    else:
        print_info("No hay backup de usuarios disponible.")
    print()

    # 6d. Restaurar extra (opcional)
    print("[3/3] Backup extra...")
    completos_ext = glob.glob(os.path.join(BACKUP_DIR, "backup_extra_completo_*.tar.gz.gpg"))
    if completos_ext:
        resp = input("¿Restaurar datos extra? (s/n): ").strip()
        if resp.lower()=="s":
            if restaurar_backup("extra", passphrase):
                print_correcto("Backup de datos extra restaurado correctamente.")
            else:
                print_error("Error al restaurar backup de datos extra.")
                registrar_errores(paso, "Error al restaurar backup de datos extra.")
        else:
            print_info("Backup extra omitido.")
    else:
        print_info("No hay backup extra disponible.")

    print()
    print_correcto("Restauración finalizada.")
    print_info("Es recomendable reiniciar el servidor: sudo systemctl daemon-reload && sudo reboot")
    print()


def mostrar_menu():
    print()
    print("="*100)
    print("MÓDULO 13: COPIAS DE SEGURIDAD.")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Configurar directorio y cifrado.")
    print("     2. Configurar rutas extra. [OPCIONAL]")
    print("     3. Ejecutar backup manual (completo).")
    print("     4. Programar backup automático (cron).")
    print("     5. Verificar integridad de backups. [OPCIONAL]")
    print("     6. Restaurar backups. [OPCIONAL]")
    print()
    print("     q. Salir")
    print()
        

def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    while True:
        mostrar_menu()
        opcion=input("Selecciona una opción: ").strip().lower()

        match opcion:
            case "1":
                paso1_configurar()
                volver_al_menu()
            case "2":
                paso2_configurar_extras()
                volver_al_menu()
            case "3":
                paso3_backup_manual()
                volver_al_menu()
            case "4":
                paso4_programar_cron()
                volver_al_menu()
            case "5":
                paso5_verificar_integridad()
                volver_al_menu()
            case "6":
                paso6_restaurar()
                volver_al_menu()
            case "q":
                print()
                print_info("Saliendo del script...")
                sys.exit(0)
            case _:
                print_error("Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()

