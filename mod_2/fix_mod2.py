#!/usr/bin/env python3
#============================================================================================================
# fix_mod2.py -  Script de hardening: Hardening General del SO
#============================================================================================================
# Este script implementa las siguientes medidas de seguridad en Ubuntu Server:
#
#   Paso 1: Actualizar kernel y sistema
#   Paso 2: Personalizar MOTD para eliminar información sensible
#   Paso 3: Configurar banners de inicio de sesión
#   Paso 4: Eliminar paquetes innecesarios u huérfanos
#   Paso 5: Configurar verificación de integridad de paquetes (GPG)
#   Paso 6: Configurar actualizaciones automáticas de seguridad
#   Paso 7: Detener y deshabilitar servicios innecesarios
#   Paso 8: Documentar servicios autorizados (un servicio por sistema)
#   Paso 9: Habilitar NTP/Chronyd
#   Paso 10: Restringir cronjobs a usuarios autorizados
#   Paso 11: Cambiar contraseñas por defecto y bloquear cuentas inseguras
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo2_fix.log
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#============================================================================================================



import os
import sys
import subprocess
import re
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, 
                   comprobar_root,
                   ejecutar_comando, 
                   volver_al_menu, 
                   escribir_fichero, 
                   leer_fichero,
                   print_aviso,
                   print_correcto,
                   print_error,
                   print_info)


#============================================================================================================
# CONSTANTES
#============================================================================================================
# Fichero de log para este módulo
LOG_FILE="/var/log/hardening/modulo2_fix.log"

# Directorio de scripts dinámicos del MOTD
MOTD_DIR="/etc/update-motd.d"

# Fichero estático del MOTD
MOTD_FILE="/etc/motd"

# Banners de inicio de sesión
ISSUE_FILE="/etc/issue"
ISSUE_NET_FILE="/etc/issue.net"

# Configuración de APT
APT_CONF_DIR="/etc/apt/apt.conf.d"
UNATTENDED_CONF_FILE="/etc/apt/apt.conf.d/50unattended-upgrades"
AUTO_UPGRADES_FILE="/etc/apt/apt.conf.d/20auto-upgrades"
GPG_ENFORCE_FILE="/etc/apt/apt.conf.d/99-force-gpg-verify"

# Paquetes innecesarios típicamente instalados
PAQUETES_INNECESARIOS=[
    "telnet", "rsh-client", "talk", "nis", "whoopsie", "apport"
]

# Servicios innecesarios típicamente existentes
SERVICIOS_INNECESARIOS=[
    "cups.service",
    "avahi-daemon.service",
    "apport.service",
    "whoopsie.service",
    "accounts-daemon.service"
]

# Documentación de servicios autorizados.
SERVICIOS_AUTORIZADOS_FILE="/etc/servicios-autorizados.txt"

# Banner para el MOTD
TEXTO_MOTD_SCRIPT="""#!/bin/bash
# =============================================================================
# Banner MOTD personalizado — Hardening Ubuntu Server
# =============================================================================
echo "***********************************************************************"
echo "*                                                                     *"
echo "*   AVISO LEGAL: Este sistema es propiedad de la organización.        *"
echo "*   El acceso no autorizado está prohibido y será perseguido          *"
echo "*   conforme a la legislación vigente (CP art. 197 bis, RGPD).        *"
echo "*                                                                     *"
echo "*   Todas las actividades en este sistema son monitorizadas           *"
echo "*   y registradas. El uso continuado implica la aceptación            *"
echo "*   de las politicas de seguridad de la organización.                 *"
echo "*                                                                     *"
echo "***********************************************************************"
"""

# Banner legal para issue/issue.net
TEXTO_BANNER="""*******************************************************************
*  ATENCIÓN: Sistema restringido. Solo personal autorizado.       *
*  Todo acceso queda registrado. El uso no autorizado será        *
*  perseguido conforme a la legislación vigente.                  *
*******************************************************************
"""

# Ficheros de control de cron
CRON_ALLOW_FILE="/etc/cron.allow"
CRON_DENY_FILE="/etc/cron.deny"
AT_ALLOW_FILE="/etc/at.allow"
AT_DENY_FILE="/etc/at.deny"

# Fichero de configuración de chrony
CHRONY_CONF="/etc/chrony/chrony.conf"

#Directorios de cron del sistema
DIRECTORIOS_CRON=[
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly"
]

# Ficheros de contraseñas
SHADOW_FILE="/etc/shadow"
PASSWD_FILE="/etc/passwd"


def paso1_actualizar_sistema():
    """
    Actualiza la lista de paquetes y aplica todas las actualizaciones disponibles,
    incluyendo las del kernel.

    Proceso:
        1. Actualizar indices de repositorios
        2. Aplicar actualizaciones
        3. Aplicar actualizaciones con cambios de dependencias
        4. Comprobar si se requiere reinicio
    """

    print()
    print("="*100)
    print("[PASO 4]: Actualizar kernel y sistema.")
    print("="*100)
    print()
    print_info("Esta medida aplica todos los parches de seguridad disponibles\n" \
    "           para cerrar vulnerabilidad conocidas (CVEs).")
    print()

    # 4a. Actualizar índices
    print_info("Actualizando lista de paquetes...")
    ejecutar_comando(["apt", "update"], "actualizar lista de paquetes", "Paso 4", mostrarSalida=True)
    print_correcto("Lista actualizada.")

    # 4b. Aplicar actualizaciones
    print_info("Aplicando actualizaciones (apt upgrade)...")
    ejecutar_comando(["apt", "upgrade", "-y"], "aplicar actualizaciones", "Paso 4", mostrarSalida=True)
    print_correcto("Actualizaciones aplicadas.")

    # 4c. Actualizaciones con cambios de dependencias
    print_info("Aplicando actualizaciones con dependencias (apt dist-upgrade)...")
    ejecutar_comando(["apt", "dist-upgrade", "-y"], "aplicar dist-upgrade", "Paso 4", mostrarSalida=True)
    print_correcto("dist-upgrade completado.")

    # 4d. Comprobar reinicio pendiente
    if os.path.isfile("/var/run/reboot-required"):
        print()
        print("="*100)
        print_aviso("Se rquiere REINICIO para aplicar actualizaciones del kernel. ")
        print_aviso("Planifica un reinicio en la próxima ventana de mantenimiento.")
        print("="*100)
    else:
        print_info("No se requiere reinicio.")
    
    print()
    print_info("Sistema actualizado.")


def paso2_personalizar_motd():
    """
    Personaliza el MOTD para eliminar información sensible del sistema.
    Deshabilita los scripts dinámicos por defecto y crea un banner legal.

    Proceso:
        1. Quitar permisos de ejecución a todos los scripts por defecto
        2. Crear un script personalizado con aviso legal
        3. Vaciar /etc/motd estático
    """
    print()
    print("="*100)
    print("[PASO 1]: Personalizar MOTD (Message of the Day)")
    print("="*100)
    print_info("Esta medida elimina la información del sistema que Ubuntu muestra tras\n" \
    "           el login (versión SO, kernel, paquetes pendientes) y la sustituye por un aviso legal.")
    print()

    # 1a. Deshabilitar scripts dinámicos por defecto
    if os.path.isdir(MOTD_DIR):
        print_info(f"Deshabilitando scripts dinámicos en {MOTD_DIR}...")
        for fichero in os.listdir(MOTD_DIR):
            rutaCompleta=os.path.join(MOTD_DIR, fichero)
            if os.path.isfile(rutaCompleta):
                statActual=os.stat(rutaCompleta)
                nuevosPermisos=statActual.st_mode & ~0o111
                os.chmod(rutaCompleta, nuevosPermisos)
        print_correcto("Scripts por defecto deshabilitados.")
    else:
        print_aviso(f"Directorio {MOTD_DIR} no encontrado.")

    # 1b. Crear script MOTD personalizado
    rutaScriptCustom=os.path.join(MOTD_DIR, "01-banner-custom")
    print_info(f"Creando script personalizado en {rutaScriptCustom}...")
    if escribir_fichero(rutaScriptCustom, TEXTO_MOTD_SCRIPT, 0o700, "Paso 1"):
        print_correcto(f"Script personalizado creado con permisos de ejecución.")

    # 1c. Vaciar /etc/motd estático
    print_info(f"Vaciando {MOTD_FILE}...")
    if escribir_fichero(MOTD_FILE, "", 0o644, "Paso 1"):
        print_correcto(f"{MOTD_FILE} vaciado.")

    print()
    print_info("PASO 1 COMPLETADO.")
    print_info("Los scripts por defecto están deshabilitados.")
    print_info("Se mostrará un aviso legal tras el login.")


def paso3_configurar_banners():
    """
    Configura los banners de /etc/issue y /etc/issue.net para eliminar información sensible y añadir
    un aviso legal.

    Proceso:
        1. Sobreescribir /etc/issue con banner legal
        2. Sobreescribir /etc/issue.net con banner legal
    """
    print()
    print("="*100)
    print("[PASO 2]: Configurar banners de inicio de sesión")
    print("="*100)
    print_info("Esta medida elimina la información del sistema que\n" \
    "           Ubuntu muestra ANTES del login (consola local).")
    print()

    # 2a. Sobrescribir /etc/issue
    print_info(f"Escribiendo banner legal en {ISSUE_FILE}...")
    if escribir_fichero(ISSUE_FILE, TEXTO_BANNER, 0o644):
        print_correcto(f"{ISSUE_FILE} configurado.")
    
    # 2b. Sobrescribir /etc/issue.net
    print_info(f"Escribiendo banner legal en {ISSUE_NET_FILE}...")
    if escribir_fichero(ISSUE_NET_FILE, TEXTO_BANNER, 0o644):
        print_correcto(f"{ISSUE_NET_FILE} configurado.")

    print()
    print_info("PASO 2 COMPLETADO.")
    print_info("Banners de inicio de sesión configurados.")
    print_info("Se muestra un aviso legal en consola local y SSH.")
    print()



def paso4_eliminar_paquetes():
    """
    Elimina paquetes huérfanos y paquetes comúnmente innecesarios en un servidor.

    Proceso:
        1. Ejecutar apt autoremove --purge para huérfanos
        2. Eliminar paquetes específicos de la lista
        3. Limpiar caché de APT
    """
    print()
    print("="*100)
    print("[PASO 3]: Eliminar paquetes innecesarios u huérfanos")
    print("="*100)
    print_info("Esta medida reduce la superficie de ataque eliminando software\n" \
    "           que no es necesario para la función del servidor.")
    print()


    # 3a. Eliminar paquetes huérfanos
    print_info("Eliminando paquetes huérfanos...")
    ejecutar_comando(
        ["apt", "autoremove", "--purge", "-y"], "eliminar paquetes huérfanos", "Paso 3"
    )
    print_correcto("Paquetes huérfanos eliminados.")

    # 3b. Eliminar paquetes específicos innecesarios
    for paquete in PAQUETES_INNECESARIOS:
        resultado= subprocess.run(["dpkg", "-l",paquete], capture_output=True, text=True)

        if resultado.returncode==0 and f"ii  {paquete}" in resultado.stdout:
            print_info(f"Eliminando paquete innecesario: {paquete}...")
            ejecutar_comando(["apt", "purge", "-y", paquete], f"eliminar {paquete}", "Paso 3")
            print_info(f"{paquete}, eliminado.")
        else:
            print_info(f"{paquete} no está instalado. Todo correcto.")
    
    # 3c. Limpiar caché de APT
    print_info("Limpiando caché de paquetes descargados...")
    ejecutar_comando(["apt", "clean"], "limpiar caché APT", "Paso 3")
    print_correcto("Caché limpia.")

    # 3d. Reparar dependencias rotas si las hay
    print_info("Verificando dependencias...")
    ejecutar_comando(["apt", "--fix-broken", "install", "-y"], "reparar dependencias", "Paso 3")

    # 3e. Segundo autoremove para eliminar nuevos paquetes huérfanos.
    print_info("Eliminando posibles nuevos paquetes huérfanos...")
    ejecutar_comando(["apt", "autoremove", "--purge", "-y"], "segundo autoremove", "Paso 3")
    print_correcto("Limpieza de huérfanos completada.")

    print()
    print_info("PASO 3 COMPLETADO.")
    print_info("Paquetes innecesarios eliminados.")
    print()


def paso5_configurar_gpg():
    """
    Configura APT para rechazar paquetes sin firma GPG válida e instala debsums para verificar
    la integridad de los paquetes instalados.

    Proces:
        1. Crea fichero de refuerzo GPG en apt.conf.d
        2. Instala debsums
    """
    print()
    print("="*100)
    print("[PASO 5]: Verificación de integridad de paquetes (GPG)")
    print("="*100)
    print()
    print_info("Esta medida asegura que APT rechace paquetes modificados o\n" \
    "           provenientes de repositorios no autenticados.")
    print()

    # 5a. Crear fichero de refuerzo GPG
    contenidoGpg=(
        'APT::Get::AllowUnauthenticated "false";\n'
        'Acquire::AllowInsecureRepositories "false";\n'
        'Acquire::AllowDowngradeToInsecureRepositories "false";\n'
    )
    print_info(f"Creando fichero de refuerzo GPG en {GPG_ENFORCE_FILE}...")
    if escribir_fichero(GPG_ENFORCE_FILE, contenidoGpg, 0o644, "Paso 5"):
        print_correcto(f"{GPG_ENFORCE_FILE} creado.")

    # 5b. Instalar debsums en el caso de que no esté instalado.
    resultado=subprocess.run(["which", "debsums"], capture_output=True, text=True)

    if resultado.returncode==0:
        print_info("debsums ya está instalado.")
    else:
        print_info("Instalando debsums...")
        ejecutar_comando(["apt", "install", "-y", "debsums"], "instalar debsums", "Paso 5")
        print_correcto("debsums instalado.")

    print()
    print_info("Integridad de paquetes configurada.")
    print_info("'debsums' disponible para verificar integridad con: sudo debsums -s")
    print()


def paso6_configurar_unattended():
    """
    Instala y configura unattended-upgrades para aplicar parches de seguridad de forma automática y diaria.

    Proceso:
        1. Instalar unattended-upgrades (si no está)
        2. Configurar 20auto-upgrades para ejecución diaria
        3. Habilitar timers de APT
    """
    print()
    print("="*100)
    print("[PASO 6]: Verificación de integridad de paquetes (GPG)")
    print("="*100)
    print()
    print_info("Esta medida configura el sistema para aplicar automáticamente\n" \
    "           los parches de seguridad, reduciendo la ventana de exposición.")
    print()

    # 6a. Instalar unattended-upgrades
    resultado=subprocess.run(["dpkg", "-l", "unattended-upgrades"], capture_output=True, text=True)

    if "ii" not in resultado.stdout:
        print_info("Instalando unattended-upgrades...")
        ejecutar_comando(["apt", "install", "-y", "unattended-upgrades"], "instalar unattended-upgrades", "Paso 6")
        print_correcto("unattended-upgrades instalado.")
    else:
        print_info("unattended-upgrades ya está instalado.")

    # 6b. Configurar periodicidad
    contenidoAutoUpgrades=(
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";\n'
        'APT::Periodic::Download-Upgradeable-Packages "1";\n'
        'APT::Periodic::AutocleanInterval "7";\n'
    )

    print_info("Configurando periodicidad...")

    if escribir_fichero(AUTO_UPGRADES_FILE, contenidoAutoUpgrades, 0o644):
        print_correcto(f"{AUTO_UPGRADES_FILE} configurado (actualizaciones diarias).")

    # 6c. Verificar y restaurar 50unattended-upgrades si es necesario. Reinstalarlo si no existiera
    contenidoUnattended =leer_fichero(UNATTENDED_CONF_FILE, "Paso 6")
    necesitaReinstalar=False

    if contenidoUnattended is None:
        necesitaReinstalar=True
    elif "security" not in contenidoUnattended.lower():
        necesitaReinstalar=True

    if necesitaReinstalar:
        print_aviso(f"{UNATTENDED_CONF_FILE} vacío o sin repositorios de seguridad.")
        print_info("Reinstalando unattended-upgrades para restaurar configuración...")


        ejecutar_comando(["apt", "install", "--reinstall", "-y", "unattended-upgrades"], "reinstalar unattended-upgrades", "Paso 6")

        contenidoUnattended=leer_fichero(UNATTENDED_CONF_FILE, "Paso 6")

    # 6d. Habilitar limpieza automática de huérfanos
    if contenidoUnattended is not None and contenidoUnattended.strip():
        lineasNuevas=[]
        yaConfigurado=False

        for linea in contenidoUnattended.splitlines():
            if "Remove-Unused-Dependencies" in linea and "Kernel" not in linea and "New" not in linea:
                if not yaConfigurado:
                    lineasNuevas.append('Unattended-Upgrade::Remove-Unused-Dependencies "true";')
                    yaConfigurado=True
            else:
                lineasNuevas.append(linea)

        if not yaConfigurado:
            lineasNuevas.append("")
            lineasNuevas.append('Unattended-Upgrade::Remove-Unused-Dependencies "true";')

        nuevoContenido="\n".join(lineasNuevas)+"\n"
        print_info(f"Habilitando Remove-Unused-Dependencies en {UNATTENDED_CONF_FILE}...")
        if escribir_fichero(UNATTENDED_CONF_FILE, nuevoContenido, 0o644, "Paso 6"):
            print_correcto("Eliminación automática de dependencias huérfanas habilitada.")
    else:
        print_aviso(f"No se pudo leer {UNATTENDED_CONF_FILE}.")

    # 6e. Habilitar y arrancar timers
    for timer in ["apt-daily.timer", "apt-daily-upgrade.timer"]:
        print_info(f"Habilitando {timer}...")
        ejecutar_comando(["systemctl", "enable", timer], f"habilitar {timer}", "Paso 6")
        ejecutar_comando(["systemctl", "start", timer], f"arrancar {timer}", "Paso 6")

    print_correcto("Timers de APT habilitados y activos.")



def paso7_deshabilitar_servicios():
    """
    Detiene y deshabilita servicios que típicamente no son necesarios en un servidor.
    Ofrece la opción de enmascararlos.

    Proceso:
        1. Detiene cada servicio innecesario
        2. Los deshabilita para que no se inicien durante el arranque
        3. Enmascararlos para máxima protección
    """
    print()
    print("="*100)
    print("[PASO 7]: Detener y deshabilitar servicios innecesarios.")
    print("="*100)
    print()
    print_info("Esta medida reduce la superficie de ataque deshabilitando\n" \
    "           servicios que no son necesarios para la función del servidor.")
    print()

    # 7a. Comprobar si el servicio existe
    for servicio in SERVICIOS_INNECESARIOS:
        resultado=subprocess.run(["systemctl", "is-enabled", servicio], capture_output=True, text=True)
        estado=resultado.stdout.strip()

        if "could not be found" in resultado.stderr or resultado.returncode==1 and estado=="":
            print_info(f"{servicio} no está instalado.")
            continue

        if estado=="masked":
            print_info(f"{servicio} ya está enmascarado (máxima protección).")
            continue
        
        # 7b. Detener el servicio si está activo
        resultadoActivo=subprocess.run(["systemctl", "is-active", servicio], capture_output=True, text=True)

        if resultadoActivo.stdout.strip()=="active":
            print_info(f"Deteniendo {servicio}...")
            ejecutar_comando(["systemctl", "stop", servicio], f"detener {servicio}", "Paso 7")

        # 7c. Deshabilitar el servicio
        print_info(f"Deshabilitando {servicio}...")
        ejecutar_comando(["systemctl", "disable", servicio], f"deshabilitar {servicio}", "Paso 7")

        # 7d. Enmascararlo para mayor protección
        print_info(f"Enmascarando {servicio}...")
        ejecutar_comando(["systemctl", "mask", servicio], f"enmascarar {servicio}", "Paso 7")

        print_correcto(f"{servicio} detenido, deshabilitado y enmascarado.")
    


def paso8_documentar_servicios():
    """
    Crea un fichero de documentación con los servicios de red actualmente activos
    para futuras auditorías. Implementa el principio de un servicio por sistema
    documentando la función del servidor.

    Proceso:
        1. Obtener la lista de servicios de red activos
        2. Crear /etc/servicios-autorizados.txt con la lista
    """
    print()
    print("="*100)
    print("[PASO 8]: Documentar servicios autorizados (un servicio por sistema)")
    print("="*100)
    print()
    print_info("Crea un fichero de documentación con los servicios de red actualmente activos\n" \
    "           para futuras auditorias. Implementa el principio de un servicio por sistema documentando\n"
    "           la función del servidor.")
    print()

    # 8a. Obtener serviciosd e red activos.
    resultado=subprocess.run(["ss", "-tulnp"], capture_output=True, text=True)

    serviciosActivos=""
    if resultado.returncode==0:
        serviciosActivos=resultado.stdout

    # 8b. Crear fichero de documentación
    fechaActual=datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    contenidoDoc=f"""#==============================================
# Servicios autorizados en este servidor
# Generado por fix_mod2.py
# Fecha: {fechaActual}
#==============================================
#
# A continuación se muestra la lista de servicios de red
# activos en el momento de ejecutar el hardening.
# Cualquier servicio que NO esté en la lista debe ser
# investigado y deshabilitado si no es necesario.
#
# Puertos en escucha al momento de la configuración:
#==============================================
{serviciosActivos}
#==============================================
# IMPORTANTE: Revisar esta lista periódicamente.
# Si se detecta un servicio nuevo no autorizado,
# deshabilitarlo inmediatamente con:
#   sudo systemctl stop <servicio>
#   sudo systemctl disable <servicio>
#==============================================
"""
    print_info(f"Creando {SERVICIOS_AUTORIZADOS_FILE}")
    if escribir_fichero(SERVICIOS_AUTORIZADOS_FILE, contenidoDoc, 0o600, "Paso 8"):
        print_correcto(f"{SERVICIOS_AUTORIZADOS_FILE} creado.")

    print()
    print_info("Servicios autorizados documentados.")
    print_info(f"Puede encontrar el documento en {SERVICIOS_AUTORIZADOS_FILE}")



def paso9_habilitar_ntp():
    """
    Instala y configura chrony para sincronización NTP, asegurando que el reloj del sistema sea preciso
    para logs, TLS u otros servicios que se puedan instalar en el futuro.

    Proceso:
        1. Instalar chrony
        2. Habilitar y arrancar el servicio
        3. Configurar zona horaria
    """
    print()
    print("="*100)
    print("[PASO 9]: Habilitar NTP/Chronyd")
    print("="*100)
    print()
    print_info("Esta medida asegura que el reloj del sistema está sincronizado para que los logs\n" \
    "           tengan timestamps correctos y los protocolos criptográficos funcionen correctamente.")
    print()

    # 9a. Instalar chrony
    resultado=subprocess.run(["dpkg", "-l", "chrony"], capture_output=True, text=True)

    if "ii" not in resultado.stdout:
        print_info("Instalando chrony...")
        ejecutar_comando(["apt", "install", "-y", "chrony"], "instalar chrony", "Paso 9")
        print_correcto("Chrony instalado.")
    else:
        print_info("Chrony ya está instalado...")

    # 9b. Habilitar y arrancar chrony
    print_info("Habilitando y arrancando chrony...")
    ejecutar_comando(["systemctl", "enable", "chrony"], "habilitar chrony", "Paso 9")
    ejecutar_comando(["systemctl", "start", "chrony"], "arrancar chrony", "Paso 9")
    print_correcto("Chrony Habilitado y activo.")

    # 9c. Configurar makestep para corregir desfases grandes
    contenido=leer_fichero(CHRONY_CONF)
    if contenido is not None:
        if re.search(r"^makestep\s+1\s+-1", contenido, re.MULTILINE):
            print_correcto("Makestep ya configurado para corregir desfases grandes.")
        else:
            nuevoContenido=re.sub(r"^makestep\s+.*$", "makestep 1 -1", contenido, flags=re.MULTILINE)

            if nuevoContenido==contenido:
                #Si no hay línea makestep, hay que añadirla
                nuevoContenido=contenido.rstrip("\n")+"\nmakestep 1 -1\n"
            if not escribir_fichero(CHRONY_CONF, nuevoContenido, paso="Paso 9"):
                print_aviso("No se pudo configurar chrony. Es posible que existan desfases temporales en el futuro.")
            else:
                print_correcto("Makestep configurado. Se corregirán los desfases mayores de 1 segundo.")
            #reiniciamos chrony
            if not ejecutar_comando(["systemctl", "restart", "chrony"], "reiniciar chrony", "Paso 9"):
                return
            else:
                print_correcto("Chrony reinicializado correctamente.")

    # 9d. Configurar zona horaria
    print_info("Configurando zona horaria a Europe/Madrid...")
    ejecutar_comando(["timedatectl", "set-timezone", "Europe/Madrid"], "configurar zona horaria", "Paso 9")
    print_correcto("Zona horaria: Europe/Madrid.")

    # 9e. Verificar sincronización
    print_info("Verificando sincronización NTP...")
    salidaChrony=ejecutar_comando(["chronyc", "tracking"], "verificar sincronización NTP", "Paso 9", capturarSalida=True)

    if salidaChrony is not None:
        print_correcto("Chrony está sincronizando.")
        for linea in salidaChrony.splitlines():
            if "Reference ID" in linea or "System time" in linea or "Frequency" in linea:
                print(f"    {linea.strip()}")

    print()
    print_info("NTP/Chronyd habilitad.\nEl reloj del sistema se sincroniza automáticamente.")



def paso10_restringir_cron():
    """
    Restringe el acceso a cron y at a solo los usuarios autorizados mediante los ficheros
    cron.allow y at.allow

    Proceso:
        1. Crear /etc/cron.allow con solo root
        2. Eliminar /etc/cron.deny (si existe)
        3. Crear /etc/at.allow con solo root
        4. Eliminar /etc/at.deny (si existe)
        5. proteger directorios de cron del sistema.
    """
    print()
    print("="*100)
    print("[PASO 10]: Restringir cronjobs a usuarios autorizados")
    print("="*100)
    print()
    print_info("Esta medida impide que usuarios no autorizados programen tareasn\n" \
    "           con cron o at, evitando la persistencia de un atacante.")
    print()


    # 10a. Crear /etc/cron.allow
    print_info(f"Creando {CRON_ALLOW_FILE} (solo root)...")
    if escribir_fichero(CRON_ALLOW_FILE, "root\n", 0o640):
        os.chown(CRON_ALLOW_FILE, 0, 0)
        print_correcto(f"{CRON_ALLOW_FILE} creado (permiso solo root).")
    
    # 10b. Eliminar /etc/cron.deny
    if os.path.isfile(CRON_DENY_FILE):
        print_info(f"Eliminando {CRON_DENY_FILE} (cron.allow tiene prioridad)...")
        os.remove(CRON_DENY_FILE)
        print_correcto(f"{CRON_DENY_FILE} eliminado.")

    # 10c. Crear /etc/at.allow
    if escribir_fichero(AT_ALLOW_FILE, "root\n", 0o640):
        print_info(f"Creando {AT_ALLOW_FILE} (solo root).")
        os.chown(AT_ALLOW_FILE, 0, 0)
        print_correcto(f"{AT_ALLOW_FILE} creado (permiso solo root).")

    # 10d. Eliminar /etc/at.deny   
    if os.path.isfile(AT_DENY_FILE):
        print_info(f"Eliminando {AT_DENY_FILE}...")
        os.remove(AT_DENY_FILE)
        print_correcto(f"{AT_DENY_FILE} eliminado.")

    # 10e. Proteger directorios de cron
    print_info("Protegiendo directorios de cron del sistema...")
    for directorio in DIRECTORIOS_CRON:
        if os.path.isdir(directorio):
            os.chmod(directorio, 0o700)
            print_correcto(f"{directorio} tiene permisos 700")
    
    print()
    print_info("Cronjobs restringidos.")
    print_info("Solo root puede crear cronjobs y tareas 'at'.")


def paso11_asegurar_contrasenas():
    """
    Busca y corrige cuentas con contraseñas vacías, bloquea la cuenta root (si se usa sudo) y
    asegura que las cuentas de servicio no tengan shell interactiva.

    Proceso:
        1. Detectar cuentas con contraseña vacía y bloquarlas
        2. Bloquar la cuenta root
        3. Cambiar la shell de cuentas de servicio con shell interactiva
    """
    print()
    print("="*100)
    print("[PASO 11]: Cambiar contraseñas por defecto y bloquear cuentas")
    print("="*100)
    print()
    print_info("Esta medida asegura que no existen cuentas con contraseñas vacías o por defecto,\n" \
    "           y que las cuentas de servicio no pueden iniciar sesión interactivamente.")
    print()

    # 11a. Detectar y bloquear cuentas con contraseña vacía
    contenidoShadow=leer_fichero(SHADOW_FILE)

    if contenidoShadow is not None:
        cuentasVacias=[]
        
        for linea in contenidoShadow.splitlines():
            if not linea.strip():
                continue
            campos=linea.split(":")
            if len(campos) >=2:
                usuario=campos[0]
                hashContrasena=campos[1]
                if hashContrasena=="":
                    cuentasVacias.append(usuario)
        
        if cuentasVacias:
            print_aviso(f"Cuentas con contraseña VACÍA: {', '.join(cuentasVacias)}")
            for cuenta in cuentasVacias:
                print_info(f"Bloqueando cuenta sin contraseña: {cuenta}")
                ejecutar_comando(["passwd", "-l", cuenta], f"bloquear cuenta {cuenta}", "Paso 11")
                print_correcto(f"{cuenta} bloqueada.")
        else:
            print_correcto("No hay cuentas con contraseña vacía.")
    else:
        print_error(f"No se pudo leer {SHADOW_FILE}.")

    # 11b. Bloquear cuenta root.
    resultado=subprocess.run(["passwd", "-S", "root"], capture_output=True, text=True)

    if resultado.returncode==0:
        campos=resultado.stdout.split()
        if len(campos)>=2 and campos[1]!="L":
            print_info("Bloqueando cuenta root. Se permitirá solo el acceso mediante sudo.")
            ejecutar_comando(["passwd", "-l", "root"], "bloquear root", "Paso 11")
            print_correcto("Cuenta root bloqueada.")
        else:
            print_info("Cuenta root ya está bloqueada.")
    
    # 11c. Asegurar cuentas de servicio
    contenidoPasswd=leer_fichero(PASSWD_FILE)
    if contenidoPasswd is not None:
        for linea in contenidoPasswd.splitlines():
            if not linea.strip():
                continue
            campos=linea.split(":")
            if len(campos)>=7:
                usuario=campos[0]
                uid=int(campos[2])
                shell=campos[6]

                if uid>0 and uid<1000:
                    if ("nologin" not in shell and "/false" not in shell and "sync" not in shell):
                        print_info(f"Cambiando shell de cuenta de servicio: {usuario} ({shell}->/usr/sbin/nologin)...")
                        ejecutar_comando(["usermod", "-s", "/usr/bin/nologin", usuario], f"cambiar shell de {usuario}", "Paso 11")
                        print_correcto(f"El usuario {usuario} ya no puede iniciar sesión.")
        


def mostrar_menu():
    """
    Muestra el menú principal del script.
    """
    print()
    print("="*100)
    print("MÓDULO 2: Hardening General del Sistema Operativo - Ubuntu Server 24.04")
    print("="*100)
    print()
    print("     Pasos disponibles:")
    print("         1. Personalizar MOTD")
    print("         2. Configurar banners de inicio de sesión")
    print("         3. Eliminar paquetes innecesarios")
    print("         4. Actualizar kernel y sistema")
    print("         5. Verificación de integridad de paquetes (GPG)")
    print("         6. Actualizaciones automáticas de seguridad")
    print("         7. Deshabilitar servicios innecesarios")
    print("         8. Documentar servicios autorizados")
    print("         9. Habilitar NTP/Chronyd")
    print("         10. Restringir cronjobs")
    print("         11. Asegurar contraseñas y cuentas")
    print()
    print("         q. Salir")
    print()

def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    while True:
        mostrar_menu()
        opcion=input("Selecciona una opción: ").strip().lower()

        match opcion:
            case "1":
                paso1_personalizar_motd()
                volver_al_menu()
            case "2":
                paso2_configurar_banners()
                volver_al_menu()
            case "3":
                paso3_eliminar_paquetes()
                volver_al_menu()
            case "4":
                paso4_actualizar_sistema()
                volver_al_menu()
            case "5":
                paso5_configurar_gpg()
                volver_al_menu()
            case "6":
                paso6_configurar_unattended()
                volver_al_menu()
            case "7":
                paso7_deshabilitar_servicios()
                volver_al_menu()
            case "8":
                paso8_documentar_servicios()
                volver_al_menu()
            case "9":
                paso9_habilitar_ntp()
                volver_al_menu()
            case "10":
                paso10_restringir_cron()
                volver_al_menu()
            case "11":
                paso11_asegurar_contrasenas()
                volver_al_menu()
            case "q":
                print_info("\nSaliendo del script.")
                sys.exit(0)
            case _:
                print_error("Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()

