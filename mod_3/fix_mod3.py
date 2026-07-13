#!/usr/bin/env python3
#============================================================================================================
# fix_mod3.py -  Script de hardening: Usuarios y Grupos
#============================================================================================================
# Este script implementa las siguientes medidas de seguridad en Ubuntu Server:
#
#   Paso 1: Auditar /etc/passwd (usuarios del sistema)
#   Paso 2: Auditar grupos y pertenencia
#   Paso 3: Configuración segura de sudo
#   Paso 4: Proteger /etc/shadow
#   Paso 5: Configurar /etc/login.defs
#   Paso 6: Aplicar envejecimiento a usuarios existentes
#   Paso 7: Deshabilitar cuentas sin contraseña
#   Paso 8: Bloquear usuarios no-root con UID 0
#   Paso 9: Bloqueo automático de cuentas inactivas.
#   Paso 10: Restringir acceso root directo
#   Paso 11: Asegurar permisos de directorios home y ficheros de inicialización.
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo2_fix.log
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#============================================================================================================



import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__),".."))
from utils import (configurar_logging, 
                   registrar_errores, 
                   comprobar_root,
                   ejecutar_comando, 
                   volver_al_menu, 
                   escribir_fichero, 
                   leer_fichero, 
                   cambiar_permisos,
                   obtener_permisos,
                   ejecutar_comando_check,
                   print_info,
                   print_aviso,
                   print_correcto,
                   print_error
                   )

#============================================================================================================
# CONSTANTES
#============================================================================================================

PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"
LOGIN_DEFS_FILE="/etc/login.defs"
SUDOERS_DIR="/etc/sudoers.d"
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
LOG_FILE="/var/log/hardening/modulo3_fix.log"

GRUPOS_SENSIBLES=["root", "sudo", "adm", "shadow", "disk", "docker"]

CONTENIDO_SUDO_HARDENING=(
    "# Configuración de hardening para sudo\n"
    "# Generado por fix_mod3.py\n"
    "#========================================================\n"
    "\n"
    "# Registrar todos los comandos ejecutados con sudo\n"
    'Defaults   logfile="/var/log/sudo.log"\n'
    "Defaults   log_input, log_output\n"
    "\n"
    "# Timeout de 5 minutos (por defecto es 15)\n"
    "Defaults   timestamp_timeout=5\n"
    "\n"
    "# Máximo 3 intentos de contraseña\n"
    "Defaults   passwd_tries=3\n"
    "\n"
    "# Mostrar aviso al usar sudo\n"
    'Defaults   lecture="always"\n'
    "\n"
    "# Requerir TTY para usar sudo\n"
    "Defaults   requiretty\n"
)

PARAMETROS_LOGIN_DEFS={
    "PASS_MAX_DAYS": "90",
    "PASS_MIN_DAYS": "7",
    "PASS_WARN_AGE": "14",
    "PASS_MIN_LEN": "12",
    "ENCRYPT_METHOD": "yescrypt",
    "UMASK": "27"
}

SHELLS_INTERACTIVAS=[
    "/bin/bash", 
    "/bin/sh", 
    "/bin/zsh", 
    "/bin/ksh", 
    "/bin/csh", 
    "/bin/fish"
    ]

FICHEROS_INIT=[
    ".bashrc", 
    ".bash_profile", 
    ".bash_logout", 
    ".profile", 
    ".bash_login", 
    ".kshrc", 
    ".cshrc", 
    ".login", 
    ".exrc", 
    ".tcshrc", 
    ".zshrc"
]
#============================================================================================================

def paso1_auditar_passwd():
    """
    Audita /etc/passwd y ofrece cambiar la shell de las cuentas de servicio que tengan
    shell interactiva a /usr/sbin/nologin
    """
    print()
    print("="*100)
    print("[PASO 1]: Auditar /etc/passwd")
    print("="*100)
    print_info("Revisa las cuentas del sistema y cambia la shell de las cuentas de servicio\n" \
    "       a /usr/sbin/nologin para impedir su uso interactivo.")
    print()

    
    contenido=leer_fichero(PASSWD_FILE, paso="Paso 1")
    if contenido is None:
        print_error("No se puede leer /etc/passwd.")
        return
    
    # 1a. Corregiro permisos de /etc/passwd
    permisos=obtener_permisos(PASSWD_FILE)
    if permisos !="644":
        print_info(f"Corrigiendo permisos de {PASSWD_FILE} de {permisos} a 644...")
        cambiar_permisos(PASSWD_FILE, permisos=0o644, paso="Paso 1")
        print_correcto("Permisos corregidos.")
    else:
        print_correcto(f"Permisos de {PASSWD_FILE} correctos (644).")

    # 1b. Buscar cuentas de servicio con shell interactiva.
    cuentasServicio=[]

    for linea in contenido.strip().splitlines():
        campos=linea.split(":")

        if len(campos)==7:
            nombre=campos[0]
            uid=int(campos[2])
            shell=campos[6]
            
            if 0<uid<1000 and shell in SHELLS_INTERACTIVAS:
                cuentasServicio.append((nombre, uid, shell))

    if not cuentasServicio:
        print_correcto("Ninguna cuenta de servicio tiene shell interactiva.")
    else:
        print_aviso(f"Se encontraron {len(cuentasServicio)} cuenta(s) de servicio con shell interactiva:")
        for nombre, uid, shell in cuentasServicio:
            print(f"        - {nombre} (UID={uid}, shell={shell})")

        print()
        respuesta=input("¿Cambiar sus shells a /usr/sbin/nologin? (s/n): ").strip().lower()
        if respuesta=="s":
            for nombre, uid, shell in cuentasServicio:
                ejecutar_comando(["usermod", "-s", "/usr/sbin/nologin", nombre], f"cambiar shell de {nombre}", "Paso 1")
                print_correcto(f"Shell de '{nombre}' cambiada a /usr/sbin/nologin.")
                print()
        else:
            print_info("No se realizaron cambios.")
            print()
    
    print()
    print_info("PASO 1 COMPLETADO.")
    print_info("Shell cambiadas y passwd auditado.")
    print()



def paso2_auditar_grupos():
    """
    Muestra los miembros de los grupos sensibles y permite eliminar usuarios de grupos
    a los que no deberían pertencer.
    """
    print()
    print("="*100)
    print_info("[PASO 2]: Auditar grupos y pertenencia")
    print("="*100)
    print_info("Muestra los miembros de grupos sensibles y permite\n" \
    "       eliminar usuarios que no deberían pertenecer a ellos.")
    print()

    # 2a. Listar miembros de grupos sensibles.
    for grupo in GRUPOS_SENSIBLES:
        rc, salida, _ =ejecutar_comando_check(["getent", "group", grupo])

        if rc==0:
            campos=salida.strip().split(":")
            miembros=campos[3] if len(campos)>3 and campos[3] else "(sin miembros)"
            print(f"{grupo}: {miembros}")
        else:
            print(f"{grupo}: No existe")
        
    print()
    print_info("Si necesitas eliminar un usuario de un grupo:")
    print_info("sudo gpasswd -d <usuario> <grupo>")
    print()

    # 2b. Ofrecer eliminación de usuario de un grupo
    respuesta=input("¿Quieres eliminar algún usuario de un grupo? (s/n): ").strip().lower()
    if respuesta=="s":
        usuario=input("Nombre del usuario: ")
        grupo=input("Nombre del grupo: ")

        if usuario and grupo:
            ejecutar_comando(["gpasswd", "-d",  usuario, grupo], f"eliminar '{usuario}' del grupo '{grupo}'", "Paso 2")
            print_correcto(f"Usuario '{usuario}' eliminando del grupo '{grupo}'.")
    else:
        print_info("No se realizaron cambios.")


def paso3_configurar_sudo():
    """
    Crea un fichero de configuración de hardening para sudo en /etc/sudoers.d/hardening
    con las directivas de seguridad recomendadas.
    """
    print()
    print("="*100)
    print("[PASO 3]: Configurar sudo")
    print("="*100)
    print("Crea un fichero de configuración en /etc/sudoers.d/ con directivas de seguridad.")
    print()

    # 3a. Crear fichero de hardening en sudoers.d
    rutaHardening=os.path.join(SUDOERS_DIR, "hardening")

    if os.path.isfile(rutaHardening):
        print_info(f"Ya existe {rutaHardening}.")

        contenidoActual=leer_fichero(rutaHardening, paso="Paso 3")

        if contenidoActual:
            print_info("Contenido actual:")
            print(contenidoActual)
        
        respuesta=input("¿Sobreescribir con la configuración recomendada? (s/n): ").strip().lower()

        if respuesta!="s":
            print_info("No se realizaron cambios")
            return
        
    print_info("Creando configuración de hardening para sudo...")
    exito=escribir_fichero(rutaHardening, CONTENIDO_SUDO_HARDENING, permisos=0o440, paso="Paso 3")

    if exito:
        cambiar_permisos(rutaHardening, permisos=0o440, propietario=0, grupo=0, paso="Paso 3")
        print_correcto(f"Configuración de hardening creada en {rutaHardening}.")
        ejecutar_comando(["visudo", "-c"], "validar configuración de sudoers", "Paso 3")
        print_correcto("Configuración de sudoers validada.")
    else:
        print_error("No se pudo crear el fichero de hardening.")

    # 3b. Buscar y advertir sobre reglas NOPASSWD
    print()
    rc, salida, _=ejecutar_comando_check(["grep", "-r", "NOPASSWD", "/etc/sudoers", SUDOERS_DIR])

    if salida.strip():
        lineasActivas=[l for l in salida.strip().splitlines() if not l.strip().startswith("#")]
        if lineasActivas:
            print_aviso("Se encontraron reglas NOPASSWD activas:")
            for linea in lineasActivas:
                print(f"    {linea}")
            print_aviso("Revisa si son necesarias.")
    else:
        print_correcto("No hay reglas NOPASSWD.")


def paso4_proteger_shadow():
    """
    Establece los permisos y propietario correctos de /etc/shadow
    """
    print()
    print("="*100)
    print("[PASO 4]: Proteger Shadow")
    print("="*100)
    print_info("Establece permisos 640 y propietario root:shadow en /etc/shadow,\n" \
    "       para que solo root y el grupo shadow puedan leer los hashes.")
    print_info("")
    print()

    if not os.path.isfile(SHADOW_FILE):
        registrar_errores("Paso 4", f"No se encontró {SHADOW_FILE}.")
        return
    
    # 4a. Corregir permisos de /etc/shadow
    permisos=obtener_permisos(SHADOW_FILE)
    if permisos not in ["640", "600"]:
        print_info(f"Corrigiendo permisos de {SHADOW_FILE} de {permisos} a 640...")
        cambiar_permisos(SHADOW_FILE, permisos=0o640, paso="Paso 4")
        print_correcto("Permisos corregidos a 640.")
    else:
        print_correcto(f"Permisos de {SHADOW_FILE} correctos ({permisos}).")

    # 4b. Corregir propietario de /etc/shadow
    infoStat=os.stat(SHADOW_FILE)
    if infoStat.st_uid !=0:
        print_info(f"Corrigiendo propietario de {SHADOW_FILE}...")
        cambiar_permisos(SHADOW_FILE, propietario=0, paso="Paso 4")
        print_correcto("Propietario corregido a root.")
    else:
        print_correcto(f"{SHADOW_FILE} ya es propiedad de root.")

    # 4c. Verificar algoritmos de hash
    contenido=leer_fichero(SHADOW_FILE, paso="Paso 4")
    if contenido:
        algoritmosDebiles=[]
        for linea in contenido.strip().splitlines():
            campos=linea.split(":")
            if len(campos) >= 2:
                hashCampo=campos[1]
                nombre=campos[0]

                if hashCampo.startswith("$1$"):
                    algoritmosDebiles.append(f"{nombre} (MD5)")
                elif hashCampo.startswith("$5$"):
                    algoritmosDebiles.append(f"{nombre} (SHA-256)")

        if algoritmosDebiles:
            print()
            print_aviso("Usuarios con algoritmos de hash débiles:")
            for alerta in algoritmosDebiles:
                print(f"    - {alerta}")
            print_aviso("Se recomienda forzar el cambio de contraseña: sudo chage -d 0 <usuario>")
        else:
            print_correcto("Todos los usuarios usan algoritmos de hash seguros.")
 

def paso5_configurar_login_defs():
    """
    Configura los parámetros de política de contraseñas en /etc/login.defs
    """
    print()
    print("="*100)
    print("[PASO 5]: Configurar /etc/login.defs")
    print("="*100)
    print_info("Configura la política de contraseñas.")
    print()

    contenido=leer_fichero(LOGIN_DEFS_FILE, paso="Paso 5")
    if contenido is None:
        return
    
    lineasModificadas=contenido.split("\n")
    cambiosRealizados=0

    # 5a. Modificar los parámetros si no lo están.
    for parametro, valorNuevo in PARAMETROS_LOGIN_DEFS.items():
        encontrado=False

        for i, linea in enumerate(lineasModificadas):
            lineaLimpia=linea.strip()

            if lineaLimpia.startswith(parametro) or lineaLimpia.startswith(f"#{parametro}") or lineaLimpia.startswith(f"# {parametro}"):
                partes=lineaLimpia.lstrip("# ").split()
                if len(partes) >=1 and partes[0]==parametro:
                    valorActual=partes[1] if len(partes) >=2 else "(sin valor)"
                    if valorActual!= valorNuevo or lineaLimpia.startswith("#"):
                        lineasModificadas[i]=f"{parametro}\t\t{valorNuevo}"
                        print_correcto(f"{parametro}: {valorActual} -> {valorNuevo}")
                        cambiosRealizados+=1
                    else:
                        print_correcto(f"{parametro} ya tiene el valor correcto ({valorActual}).")
                    encontrado=True
                    break
        # 5b. Añadir los parámetros en caso de que no existan
        if not encontrado:
            lineasModificadas.append(f"{parametro}\t\t{valorNuevo}")
            print_correcto(f"{parametro}: añadido con valor {valorNuevo}")
            cambiosRealizados+=1

    # 5c. Escribir los parámetros.
    if cambiosRealizados>0:
        nuevoContenido="\n".join(lineasModificadas)+"\n"

        exito=escribir_fichero(LOGIN_DEFS_FILE, nuevoContenido, permisos=0o600, paso="Paso 5")

        if exito:
            print(f"\n[CORRECTO]: {cambiosRealizados} parámetro(s) actualizado(s) en {LOGIN_DEFS_FILE}.")
        else:
            print(f"\n[ERROR]: No se puede escribir en {LOGIN_DEFS_FILE}.")
    else:
        print_correcto("Todos los parámetros ya tienen los valores correctos.")

    
def paso6_envejecimiento_contrasenas():
    """
    Aplica la política de envejecimiento de contraseñas a todos los usuarios humanos 
    existentes (UID >= 1000)
    """
    print()
    print("="*100)
    print("[PASO 6]: Envejecimiento de contraseñas en usuarios existentes.")
    print("="*100)
    print_info("Aplica con chage la política de caducidad a los usuarios existentes.")
    print()

    contenido=leer_fichero(PASSWD_FILE, paso="Paso 6")

    if contenido is None:
        return
    
    usuariosHumanos=[]

    # 6a. Obtener lista de usuarios humanos
    for linea in contenido.strip().splitlines():
        campos=linea.split(":")
        if len(campos)==7:
            uid=int(campos[2])
            if 1000<=uid<=65534:
                usuariosHumanos.append(campos[0])


    if not usuariosHumanos:
        print_info("No se encontraron usuarios.")
        return
    
    print_info(f"Se aplicará la política a {len(usuariosHumanos)} usuario(s):")
    print(f"    PASS_MAX_DAYS=90, PASS_MIN_DAYS=7, PASS_WARN_AGE=14")
    print()

    # 6b. Aplicar cambios a usuarios humanos
    for usuario in usuariosHumanos:
        if ejecutar_comando(["chage", "-M", "90", "-m", "7", "-W", "14", usuario], f"aplicar política de contraseñas a {usuario}", paso="Paso 6"):
            print_correcto(f"Política aplicada a {usuario}")


def paso7_cuentas_sin_contrasena():
    """
    Busca y bloquea cuentas con contraseña vacía.
    """
    print()
    print("="*100)
    print("[PASO 7]: Deshabilitar cuentas sin contraseña.")
    print("="*100)
    print_info("Busca cuentas con contraseña vacía en /etc/shadow y las bloquea.")
    print()

    contenido=leer_fichero(SHADOW_FILE, paso="Paso 7")
    if contenido is None:
        return
    
    cuentasSinPassword=[]

    # 7a. Buscar y bloquear cuentas con contraseña vacía
    for linea in contenido.strip().splitlines():
        campos=linea.split(":")

        if len(campos)>=2 and campos[1]=="":
            cuentasSinPassword.append(campos[0])

    if not cuentasSinPassword:
        print_correcto("No hay cuentas con contraseña vacía.")
    else:
        print_aviso(f"Se encontraron {len(cuentasSinPassword)} cuentas sin contraseña:")
        for cuenta in cuentasSinPassword:
            print(f"    - {cuenta}")
        print()
        print_info("Bloqueando cuentas sin contraseña...")
        for cuenta in cuentasSinPassword:
            ejecutar_comando(["passwd", "-l", cuenta], f"bloqueando cuenta {cuenta}", paso="Paso 7")
            print_correcto(f"Cuenta '{cuenta}' bloqueada con éxito.")
    


def paso8_bloquear_uid0():
    """
    Busca y bloquea cuentas que no sean root pero tengan UID 0
    """
    print()
    print("="*100)
    print("[PASO 8]: Buscar y bloquear cuentas no-root con UID 0.")
    print("="*100)
    print_info("Busca cuentas con UID 0 que no sean root.\n" \
    "       Solo root debe tener UID 0.")
    print()


    contenido=leer_fichero(PASSWD_FILE, paso="Paso 8")
    if contenido is None:
        return
    
    cuentasUid0=[]

    # 8a. Buscar cuentas con UID 0
    for linea in contenido.strip().splitlines():
        campos=linea.split(":")
        if len(campos)==7 and campos[2] =="0" and campos[0]!="root":
            cuentasUid0.append(campos[0])

    if not cuentasUid0:
        print_correcto("Solo 'root' tiene UID 0. No hay cuentas sospechosas.")
    # 8b. Bloquear las cuentas en caso de encontarlas.
    else:
        print_aviso(f"Se encontraron {len(cuentasUid0)} cuenta(s) no-root con UID 0:")
        for cuenta in cuentasUid0:
            print(f"        - {cuenta}")
        print()
        print_info("Bloqueando cuentas sospechosas...")

        for cuenta in cuentasUid0:
            ejecutar_comando(["usermod", "-L", cuenta], f"bloquear cuenta {cuenta}", "Paso 8")
            ejecutar_comando(["usermod", "-s", "/usr/sbin/nologin", cuenta], f"cambiar shell de {cuenta}", "Paso 8")
            print_correcto(f"Cuenta '{cuenta}' bloqueada y shell cambiada a nologin.")

    
def paso9_bloqueo_inactivas():
    """
    Configura el bloqueo automático de cuentas tras un período de inactividad
    (contraseña expirada sin cambiar)
    """
    print()
    print("="*100)
    print("[PASO 9]: Bloqueo automático de cuentas inactivas.")
    print("="*100)
    print_info("Bloquea automáticamente las cuentas cuyas contraseña haya \n" \
    "       expirado y no se cambie en 30 días.")
    print()

    # 9a. Establecer INACTIVE para nuevas cuentas
    print_info("Configurando INACTIVE=30 para nuevas cuentas...")
    ejecutar_comando(["useradd", "-D", "-f", "30"], "configurar INACTIVE=30", "Paso 9")
    print_correcto("INACTIVE=30 configurado para nuevas cuentas.")
    print()

    # 9b. Aplicar INACTIVE a usuarios existentes
    contenido=leer_fichero(PASSWD_FILE, paso="Paso 9")
    if contenido is None:
        return
    
    usuariosAfectados=[]
    
    for linea in contenido.strip().splitlines():
        campos=linea.split(":")
        
        if len(campos)==7:
            uid=int(campos[2])
            if 1000<=uid<65534:
                usuariosAfectados.append(campos[0])

    if usuariosAfectados:
        print_info(f"Aplicando INACTIVE=30 a {len(usuariosAfectados)} usuario(s)...")

        for usuario in usuariosAfectados:
            ejecutar_comando(["chage", "-I", "30", usuario], f"configurar inactividad para {usuario}", "Paso 9")
            print_correcto(f"INACTIVE=30 aplicado a: {usuario}")

def paso10_restringir_root():
    """
    Restringe el acceso directo como root:
    1. Verifica qué usuarios hay en el grupo sudo
    2. Bloquear contraseña de root
    """
    print()
    print("="*100)
    print("[PASO 10]: Restringir acceso root directo.")
    print("="*100)
    print_info("Bloquea la contraseña de root.\n" \
    "       Toda administración se realizará exclusivamente a través de sudo.")
    print()

    # 10a. Verificar qué hay usuarios en el grupo sudo
    rc, salida, _=ejecutar_comando_check(["getent", "group", "sudo"])
    if rc==0:
        campos=salida.strip().split(":")
        miembros=campos[3] if len(campos) > 3 and campos[3] else ""
        if not miembros:
            print_aviso("El grupo sudo no tiene miembros.")
            print_aviso("NO se puede bloquear root sin tener acceso sudo alternativo.")
            print_aviso("Añada primero un usuario al grupo sudo: sudo usermod -aG sudo <usuario>")
            return
        else:
            print_correcto(f"Grupo sudo tiene miembros: {miembros}")

    else:
        print_error("No se pudo verificar el grupo sudo.")
        return
    
    print()

    # 10b. Bloquear contraseña de root
    rcRoot, salidaRoot, _=ejecutar_comando_check(["passwd", "-S", "root"])
    if rcRoot==0:
        estado=salidaRoot.strip().split()[1]
        if estado=="L":
            print_correcto("Contraseña de root ya está bloqueada.")
        else:
            respuesta=input("¿Bloquear la contraseña de root? (s/n): ").strip().lower()
            if respuesta=="s":
                ejecutar_comando(["passwd", "-l", "root"], "bloquear contraseña de root", "Paso 10")
                print_correcto("Contraseña de root bloqueada.")
    
    print()



def paso11_permisos_home():
    """
    Asegura que los directorios home de usuarios humanos tienen permisos 0750 y que los ficheros
    de inicialización tienen permisos 0640.
    """
    print()
    print("="*100)
    print("[PASO 10]: Restringir acceso root directo.")
    print("="*100)
    print_info("Restringe los directorios home a 0750 y los ficheros de inicialización a 0640")
    print

    paso="Paso 11"

    contenido=leer_fichero(PASSWD_FILE, paso)
    if contenido is None:
        return
    
    if contenido is None:
        return
    
    for linea in contenido.strip().splitlines():
        campos=linea.split(":")
        if len(campos) !=7:
            continue
        nombre=campos[0]
        uid=int(campos[2])
        homeDir=campos[5]

        # Buscar solo usuarios humanos con home real
        if uid<1000 or uid>65534:
            continue
        if not os.path.isdir(homeDir):
            continue

        # 11a. Permisos del directorio home (0750)
        cambiar_permisos(homeDir, permisos=0o750, paso=paso)

        # 11b. Ficheros de inicialización
        for fichero in FICHEROS_INIT:
            rutaFichero=os.path.join(homeDir, fichero)
            if not os.path.isfile(rutaFichero):
                continue
            cambiar_permisos(rutaFichero, permisos=0o640, paso=paso)
        




def mostar_menu():
    print()
    print("="*100)
    print("MÓDULO 3: Usuarios y Grupos")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Auditar /etc/passwd")
    print("     2. Auditar grupos y pertenencia")
    print("     3. Configurar sudo de forma segura")
    print("     4. Proteger /etc/shadow")
    print("     5. Configurar /etc/login.defs")
    print("     6. Envejecimiento de contraseñas (usuarios existentes)")
    print("     7. Deshabilitar cuentas sin contraseña")
    print("     8. Bloquear usuarios no-root con UID 0")
    print("     9. Bloqueo automático de cuentas inactivas")
    print("     10. Restringir acceso root directo")
    print("     11. Establecer permisos de los directorios home")
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
                paso1_auditar_passwd()
                volver_al_menu()
            case "2":
                paso2_auditar_grupos()
                volver_al_menu()
            case "3":
                paso3_configurar_sudo()
                volver_al_menu()
            case "4":
                paso4_proteger_shadow()
                volver_al_menu()
            case "5":
                paso5_configurar_login_defs()
                volver_al_menu()
            case "6":
                paso6_envejecimiento_contrasenas()
                volver_al_menu()
            case "7":
                paso7_cuentas_sin_contrasena()
                volver_al_menu() 
            case "8":
                paso8_bloquear_uid0()
                volver_al_menu()
            case "9":
                paso9_bloqueo_inactivas()
                volver_al_menu()
            case "10":
                paso10_restringir_root()
                volver_al_menu()
            case "11":
                paso11_permisos_home()
                volver_al_menu()
            case "q":
                print_info("Saliendo del script.")
                sys.exit(0)
            case _:
                print_error("Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()