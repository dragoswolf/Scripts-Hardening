#!/usr/bin/env python3

import os
import sys
import subprocess
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, registrar_errores, comprobar_root,
                   ejecutar_comando, volver_al_menu, escribir_fichero, leer_fichero)


LOG_FILE="/var/log/hardening/fix_mod2.log"

MOTD_DIR="/etc/update-motd.d"
MOTD_FILE="/etc/motd"
ISSUE_FILE="/etc/issue"
ISSUE_NET_FILE="/etc/issue.net"
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"

APT_CONF_DIR="/etc/apt/apt.conf.d"
UNATTENDED_CONF_FILE="/etc/apt/apt.conf.d/50unattended-upgrades"
AUTO_UPGRADES_FILE="/etc/apt/apt.conf.d/20auto-upgrades"
GPG_ENFORCE_FILE="/etc/apt/apt.conf.d/99-force-gpg-verify"

PAQUETES_INNECESARIOS=[
    "telnet", "rsh-client", "talk", "nis", "whoopsie", "apport"
]

SERVICIOS_INNECESARIOS=[
    "cups.service",
    "avahi-daemon.service",
    "apport.service",
    "whoopsie.service",
    "accounts-daemon.service"
]

SERVICIOS_AUTORIZADOS_FILE="/etc/servicios-autorizados.txt"

#banner para el MOTD

TEXTO_MOTD_SCRIPT="""#!/bin/bash
# =============================================================================
# Banner MOTD personalizado — Hardening Ubuntu Server
# =============================================================================
echo "***********************************************************************"
echo "*                                                                     *"
echo "*   AVISO LEGAL: Este sistema es propiedad de la organizacion.        *"
echo "*   El acceso no autorizado esta prohibido y sera perseguido          *"
echo "*   conforme a la legislacion vigente (CP art. 197 bis, RGPD).        *"
echo "*                                                                     *"
echo "*   Todas las actividades en este sistema son monitorizadas           *"
echo "*   y registradas. El uso continuado implica la aceptacion            *"
echo "*   de las politicas de seguridad de la organizacion.                 *"
echo "*                                                                     *"
echo "***********************************************************************"
"""

#banner legal para issue/issue.net
TEXTO_BANNER="""*******************************************************************
*  ATENCION: Sistema restringido. Solo personal autorizado.       *
*  Todo acceso queda registrado. El uso no autorizado sera        *
*  perseguido conforme a la legislacion vigente.                  *
*******************************************************************
"""

# Ficheros de control de cron
CRON_ALLOW_FILE="/etc/cron.allow"
CRON_DENY_FILE="/etc/cron.deny"
AT_ALLOW_FILE="/etc/at.allow"
AT_DENY_FILE="/etc/at.deny"

#Directorios de cron del sistema
DIRECTORIOS_CRON=[
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly"
]

SHADOW_FILE="/etc/shadow"
PASSWD_FILE="/etc/passwd"

def paso1_personalizar_motd():
    print()
    print("="*100)
    print("[PASO 1]: Personalizar MOTD (Message of the Day)")
    print("="*100)
    print()
    print("Esta medida elimina la información del sistema que Ubuntu muestra,")
    print("tras el login (versión SO, kernel, paquetes pendientes) y la")
    print("sustituye por un aviso legal.")
    print()

    if os.path.isdir(MOTD_DIR):
        print(f"[INFO]: Deshabilitando scripts dinámicos en {MOTD_DIR}...")
        for fichero in os.listdir(MOTD_DIR):
            rutaCompleta=os.path.join(MOTD_DIR, fichero)
            if os.path.isfile(rutaCompleta):
                if os.path.isfile(rutaCompleta):
                    statActual=os.stat(rutaCompleta)
                    nuevosPermisos=statActual.st_mode & ~0o111
                    os.chmod(rutaCompleta, nuevosPermisos)
        print("[CORRECTO]: Scripts por defecto deshabilitados.")
    else:
        print(f"[AVISO]: Directorio {MOTD_DIR} no encontrado.")

    rutaScriptCustom=os.path.join(MOTD_DIR, "01-banner-custom")
    print(f"[INFO]: Creando script personalizado en {rutaScriptCustom}...")
    if escribir_fichero(rutaScriptCustom, TEXTO_MOTD_SCRIPT, 0o700, "Paso 1"):
        print(f"[CORRECTO]: Script personalizado creado con permisos de ejecución.")

    print(f"[INFO]: Vaciando {MOTD_FILE}...")
    if escribir_fichero(MOTD_FILE, "", 0o644, "Paso 1"):
        print(f"[CORRECTO]: {MOTD_FILE} vaciado.")

    print()
    print("[CORRECTO]: Paso 1 completado correctamente.")
    print("            Los scripts por defecto están deshabilitados.")
    print("            Se mostrará un aviso legal tras el login.")


def paso2_configurar_banners():
    print()
    print("="*100)
    print("[PASO 2]: Configurar banners de inicio de sesión")
    print("="*100)
    print()
    print("Esta medida elimina la información del sistema que Ubuntu muestra,")
    print("ANTES del login (consola local y SSH).")
    print()

    print(f"[INFO]: Escribiendo banner legal en {ISSUE_FILE}...")
    if escribir_fichero(ISSUE_FILE, TEXTO_BANNER, 0o644):
        print(f"[CORRECTO]: {ISSUE_FILE} configurado.")
    
    print(f"[INFO]: Escribiendo banner legal en {ISSUE_NET_FILE}...")
    if escribir_fichero(ISSUE_NET_FILE, TEXTO_BANNER, 0o644):
        print(f"[CORRECTO]: {ISSUE_NET_FILE} configurado.")

    contenidoSshd=leer_fichero(SSHD_CONFIG_FILE)
    if contenidoSshd is not None:
        bannerYaConfigurado=False
        lineasNuevas=[]
        for linea in contenidoSshd.splitlines():
            lineaLimpia=linea.strip()
            if lineaLimpia.lower().startswith("banner") or lineaLimpia.lower().startswith("#banner"):
                if not bannerYaConfigurado:
                    lineasNuevas.append("Banner /etc/issue.net")
                    bannerYaConfigurado=True
            else:
                lineasNuevas.append(linea)

        if not bannerYaConfigurado:
            lineasNuevas.append("")
            lineasNuevas.append("# Banner legal añadido por fix_mod2.py")
            lineasNuevas.append("Banner /etc/issue.net")

        nuevoContenido="\n".join(lineasNuevas)+"\n"
        print(f"[INFO]: Configurando directiva Banner en {SSHD_CONFIG_FILE}...")
        if escribir_fichero(SSHD_CONFIG_FILE, nuevoContenido, 0o600):
            print("[CORRECTO]: Directiva 'Banner /etc/issue.net' configurada")
        
        print("[INFO]: Reiniciando servicio SSH...")
        ejecutar_comando(["systemctl", "restart", "sshd"], "reiniciar SSH", "Paso 2")
        print("[CORRECTO]: SSH reiniciado.")
    else:
        print(f"[ERROR]: No se puede leer {SSHD_CONFIG_FILE}")

    print()
    print("[CORRECTO] PASO 2 COMPLETADO CORRECTAMENTE.")
    print("Banners de inicio de sesión configurados.")
    print("Se muestra un aviso legal en consola local y SSH.")



def paso3_eliminar_paquetes():
    print()
    print("="*100)
    print("[PASO 3]: Eliminar paquetes innecesarios u huérfanos")
    print("="*100)
    print()
    print("Esta medida reduce la superficie de ataque eliminando software")
    print("que no es necesario para la función del servidor.")

    print("[INFO]: Eliminando paquetes huérfanos...")
    ejecutar_comando(
        ["apt", "autoremove", "--purge", "-y"], "eliminar paquetes huérfanos", "Paso 3"
    )

    print("[CORRECTO]: Paquetes huérfanos eliminados.")

    for paquete in PAQUETES_INNECESARIOS:
        resultado= subprocess.run(["dpkg", "-l",paquete], capture_output=True, text=True)

        if resultado.returncode==0 and f"ii  {paquete}" in resultado.stdout:
            print(f"[INFO]: Eliminando paquete innecesario: {paquete}...")
            ejecutar_comando(["apt", "purge", "-y", paquete], f"eliminar {paquete}", "Paso 3")
            print(f"[CORRECTO]: {paquete}, eliminado.")
        else:
            print(f"[INFO]: {paquete} no está instalado. Todo correcto.")
    
    print("[INFO]: Limpiando caché de paquetes descargados...")
    ejecutar_comando(["apt", "clean"], "limpiar caché APT", "Paso 3")
    print("[CORRECTO]: Caché limpia.")

    print("[INFO] Verificando dependencias...")
    ejecutar_comando(["apt", "--fix-broken", "install", "-y"], "reparar dependencias", "Paso 3")

    print("[INFO]: Eliminando posibles nuevos paquetes huérfanos...")
    ejecutar_comando(["apt", "autoremove", "--purge", "-y"], "segundo autoremove", "Paso 3")
    print("[CORRECTO]: Limpieza de huérfanos completada.")

    print()
    print("[CORRECTO]: PASO 3 completado. Paquetes innecesarios eliminados.")


def paso4_actualizar_sistema():

    print()
    print("="*100)
    print("[PASO 4]: Actualizar kernel y sistema.")
    print("="*100)
    print()
    print("Esta medida aplica todos los parches de seguridad disponibles")
    print("para cerrar vulnerabilidad conocidas (CVEs).")
    print()

    print("[INFO] Actualizando lista de paquetes...")
    ejecutar_comando(["apt", "update"], "actualizar lista de paquetes", "Paso 4", mostrarSalida=True)
    print("[CORRECTO]: Lista actualizada.")

    print("[INFO]: Aplicando actualizaciones (apt upgrade)...")
    ejecutar_comando(["apt", "upgrade", "-y"], "aplicar actualizaciones", "Paso 4", mostrarSalida=True)
    print("[CORRECTO]: Actualizaciones aplicadas.")

    print("[INFO]: Aplicando actualizaciones con dependencias (apt dist-upgrade)...")
    ejecutar_comando(["apt", "dist-upgrade", "-y"], "aplicar dist-upgrade", "Paso 4", mostrarSalida=True)
    print("[CORRECTO]: dist-upgrade completado.")

    if os.path.isfile("/var/run/reboot-required"):
        print()
        print("="*50)
        print("                 [AVISO]")
        print("Se rquiere REINICIO para aplicar actualizaciones")
        print("del kernel. Planifica un reinicio en la próxima")
        print("ventana de mantenimiento.")
        print("="*50)
    else:
        print("[INFO]: No se requiere reinicio.")
    
    print()
    print("PASO 4 COMPLETADO. SISTEMA ACTUALIZADO. SE REQUIERE VOLVER A EJECUTAR EL PASO 1")


def paso5_configurar_gpg():
    print()
    print("="*100)
    print("[PASO 5]: Verificación de integridad de paquetes (GPG)")
    print("="*100)
    print()
    print("Esta medida asegura que APT rechace paquetes modificados o")
    print("provenientes de repositorios no autenticados.")
    print()

    contenidoGpg=(
        'APT::Get::AllowUnauthenticated "false";\n'
        'Acquire::AllowInsecureRepositories "false";\n'
        'Acquire::AllowDowngradeToInsecureRepositories "false";\n'
    )
    print(f"[INFO]: Creando fichero de refuerzo GPG en {GPG_ENFORCE_FILE}...")
    if escribir_fichero(GPG_ENFORCE_FILE, contenidoGpg, 0o644, "Paso 5"):
        print(f"[CORRECTO]: {GPG_ENFORCE_FILE} creado.")

    resultado=subprocess.run(["which", "debsums"], capture_output=True, text=True)

    if resultado.returncode==0:
        print("[INFO]: debsums ya está instalado.")
    else:
        print("[INFO]: Instalando debsums...")
        ejecutar_comando(["apt", "install", "-y", "debsums"], "instalar debsums", "Paso 5")
        print("[CORRECTO]: debsums instalado.")

    print()
    print("[CORRECTO]: PASO 5 completado. Integridad de paquetes configurada.")
    print("            'debsums' disponible para verificar integridad con: sudo debsums -s")
    print()


def paso6_configurar_unattended():
    print()
    print("="*100)
    print("[PASO 6]: Verificación de integridad de paquetes (GPG)")
    print("="*100)
    print()
    print("Esta medida configura el sistema para aplicar automáticamente")
    print("los parches de seguridad, reduciendo la ventana de exposición.")
    print()

    resultado=subprocess.run(["dpkg", "-l", "unattended-upgrades"], capture_output=True, text=True)

    if "ii" not in resultado.stdout:
        print("[INFO]: Instalando unattended-upgrades...")
        ejecutar_comando(["apt", "install", "-y", "unattended-upgrades"], "instalar unattended-upgrades", "Paso 6")
        print("[CORRECTO]: unattended-upgrades instalado.")
    else:
        print("[INFO]: unattended-upgrades ya está instalado.")

    contenidoAutoUpgrades=(
        'APT::Periodic:Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";\n'
        'APT::Periodic::Download-Upgradeable-Packages "1";\n'
        'APT::Periodic::AutocleanInterval "7";\n'
    )

    print("[INFO]: Configurando periodicidad...")

    if escribir_fichero(AUTO_UPGRADES_FILE, contenidoAutoUpgrades, 0o644):
        print(f"[CORRECTO]: {AUTO_UPGRADES_FILE} configurado (actualizaciones diarias).")

    contenidoUnattended =leer_fichero(UNATTENDED_CONF_FILE, "Paso 6")


    if contenidoUnattended is not None or "security" not in contenidoUnattended.lower():
        print(f"[AVISO]: {UNATTENDED_CONF_FILE} vacío o sin repositorios de seguridad.")
        print("[INFO]: Reinstalando unattended-upgrades para restaurar configuración...")
        ejecutar_comando(["rm", "/etc/apt/apt.conf.d/50unattended-upgrades"], "eliminar fichero por defecto", "Paso 6")
        ejecutar_comando(["apt", "install", "--reinstall", "-y", "unattended-upgrades"], "reinstalar unattended-upgrades", "Paso 6")

        contenidoUnattended=leer_fichero(UNATTENDED_CONF_FILE, "Paso 6")

    if contenidoUnattended is not None and contenidoUnattended.strip():
        lineasNuevas=[]
        yaConfigurado=False

        for linea in contenidoUnattended.splitlines():
            lineaLimpia=linea.strip()
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
        print(f"[INFO]: Habilitando Remove-Unused-Dependencies en {UNATTENDED_CONF_FILE}...")
        if escribir_fichero(UNATTENDED_CONF_FILE, nuevoContenido, 0o644, "Paso 6"):
            print("[CORRECTO]: Eliminación automática de dependencias huérfanas habilitada.")
    else:
        print(f"[AVISO]: No se pudo leer {UNATTENDED_CONF_FILE}.")


    for timer in ["apt-daily.timer", "apt-daily-upgrade.timer"]:
        print(f"[INFO]: Habilitando {timer}...")
        ejecutar_comando(["systemctl", "enable", timer], f"habilitar {timer}", "Paso 6")
        ejecutar_comando(["systemctl", "start", timer], f"arrancar {timer}", "Paso 6")

    print("[CORRECTO]: Timers de APT habilitados y activos.")

    print()
    print("[CORRECTO]: PASO 6 completado. Actualizaciones automáticas configuradas.")


def paso7_deshabilitar_servicios():
    print()
    print("="*100)
    print("[PASO 7]: Detener y deshabilitar servicios innecesarios.")
    print("="*100)
    print()
    print("Esta medida reduce la superficie de ataque deshabilitando")
    print("servicios que no son necesarios para la función del servidor.")
    print()

    for servicio in SERVICIOS_INNECESARIOS:
        resultado=subprocess.run(["systemctl", "is-enabled", servicio], capture_output=True, text=True)
        estado=resultado.stdout.strip()

        if "could not be found" in resultado.stderr or resultado.returncode==1 and estado=="":
            print(f"[INFO]: {servicio} no está instalado.")
            continue

        if estado=="masked":
            print(f"[INFO] {servicio} ya está enmascarado (máxima protección).")
            continue

        resultadoActivo=subprocess.run(["systemctl", "is-active", servicio], capture_output=True, text=True)

        if resultadoActivo.stdout.strip()=="active":
            print(f"[INFO]: Deteniendo {servicio}...")
            ejecutar_comando(["systemctl", "stop", servicio], f"detener {servicio}", "Paso 7")

        print(f"[INFO]: Deshabilitando {servicio}...")
        ejecutar_comando(["systemctl", "disable", servicio], f"deshabilitar {servicio}", "Paso 7")

        print(f"[INFO]: Enmascarando {servicio}...")
        ejecutar_comando(["systemctl", "mask", servicio], f"enmascarar {servicio}", "Paso 7")

        print(f"[CORRECTO]: {servicio} detenido, deshabilitado y enmascarado.")
    
    print()
    print("[CORRECTO]: PASO 7 completado. Servicios innecesarios deshabilitados.")


def paso8_documentar_servicios():

    print()
    print("="*100)
    print("[PASO 8]: Documentar servicios autorizados (un servicio por sistema)")
    print("="*100)
    print()
    print("Esta medida reduce la superficie de ataque deshabilitando")
    print("servicios que no son necesarios para la función del servidor.")
    print()

    resultado=subprocess.run(["ss", "-tulnp"], capture_output=True, text=True)

    serviciosActivos=""
    if resultado.returncode==0:
        serviciosActivos=resultado.stdout

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
    print(f"[INFO]: Creando {SERVICIOS_AUTORIZADOS_FILE}")
    if escribir_fichero(SERVICIOS_AUTORIZADOS_FILE, contenidoDoc, 0o600, "Paso 8"):
        print(f"[CORRECTO]: {SERVICIOS_AUTORIZADOS_FILE} creado.")

    print()
    print("PASO 8 COMPLETADO. SERVICIOS AUTORIZADOS DOCUMENTADOS.")
    print(f"PUEDE ENCONTRAR EL FICHERO EN {SERVICIOS_AUTORIZADOS_FILE}")



def paso9_habilitar_ntp():
    print()
    print("="*100)
    print("[PASO 9]: Habilitar NTP/Chronyd")
    print("="*100)
    print()
    print("Esta medida asegura que el reloj del sistema está sincronizado")
    print("para que los logs tengan timestamps correctos y los protocolos")
    print("criptográficos funcionen correctamente.")
    print()

    resultado=subprocess.run(["dpkg", "-l", "chrony"], capture_output=True, text=True)

    if "ii" not in resultado.stdout:
        print("[INFO]: Instalando chrony...")
        ejecutar_comando(["apt", "install", "-y", "chrony"], "instalar chrony", "Paso 9")
        print("[CORRECTO]: Chrony instalado.")
    else:
        print("[INFO]: Chrony ya está instalado...")

    
    print("[INFO]: Habilitando y arrancando chrony...")
    ejecutar_comando(["systemctl", "enable", "chrony"], "habilitar chrony", "Paso 9")
    ejecutar_comando(["systemctl", "start", "chrony"], "arrancar chrony", "Paso 9")
    print("[CORRECTO]: Chrony Habilitado y activo.")

    print("[INFO]: Configurando zona horaria a Europe/Madrid...")
    ejecutar_comando(["timedatectl", "set-timezone", "Europe/Madrid"], "configurar zona horaria", "Paso 9")
    print("[CORRECTO]: Zona horaria: Europe/Madrid.")

    print("[INFO] Verificando sincronización NTP...")
    salidaChrony=ejecutar_comando(["chronyc", "tracking"], "verificar sincronización NTP", "Paso 9", capturarSalida=True)

    if salidaChrony is not None:
        print("[CORRECTO]: Chrony está sincronizando.")
        for linea in salidaChrony.splitlines():
            if "Reference ID" in linea or "System time" in linea or "Frequency" in linea:
                print(f"    {linea.strip()}")

    print()
    print("[CORRECTO]: PASO 9 completado. NTP/Chronyd habilitad.")
    print("            El reloj del sistema se sincroniza automáticamente.")



def paso10_restringir_cron():
    print()
    print("="*100)
    print("[PASO 10]: Restringir cronjobs a usuarios autorizados")
    print("="*100)
    print()
    print("Esta medida impide que usuarios no autorizados programen tareas")
    print("con cron o at, evitando la persistencia de un atacante.")
    print()

    print(f"[INFO] Creando {CRON_ALLOW_FILE} (solo root)...")
    if escribir_fichero(CRON_ALLOW_FILE, "root\n", 0o640):
        os.chown(CRON_ALLOW_FILE, 0, 0)
        print(f"[CORRECTO]: {CRON_ALLOW_FILE} creado (permiso solo root).")
    
    if os.path.isfile(CRON_DENY_FILE):
        print(f"[INFO]: Eliminando {CRON_DENY_FILE} (cron.allow tiene prioridad)...")
        os.remove(CRON_DENY_FILE)
        print(f"[CORRECTO]: {CRON_DENY_FILE} eliminado.")

    if escribir_fichero(AT_ALLOW_FILE, "root\n", 0o640):
        print(f"[INFO]: Creando {AT_ALLOW_FILE} (solo root).")
        os.chown(AT_ALLOW_FILE, 0, 0)
        print(f"[CORRECTO]: {AT_ALLOW_FILE} creado (permiso solo root).")
        
    if os.path.isfile(AT_DENY_FILE):
        print(f"[INFO]: Eliminando {AT_DENY_FILE}...")
        os.remove(AT_DENY_FILE)
        print(f"[CORRECTO]: {AT_DENY_FILE} eliminado.")

    print("[INFO]: Protegiendo directorios de cron del sistema...")
    for directorio in DIRECTORIOS_CRON:
        if os.path.isdir(directorio):
            os.chmod(directorio, 0o700)
            print(f"[CORRECTO]: {directorio} tiene permisos 700")
    
    print()
    print("[CORRECTO]: PASO 10 completado. Cronjobs restringidos.")
    print("            Solo root puede crear cronjobs y tareas 'at'.")


def paso11_asegurar_contrasenas():
    print()
    print("="*100)
    print("[PASO 11]: Cambiar contraseñas por defecto y bloquear cuentas")
    print("="*100)
    print()
    print("Esta medida asegura que no existen cuentas con contraseñas")
    print("vacías o por defecto, y que las cuentas de servicio no pueden")
    print("iniciar sesión interactivamente.")
    print()

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
            print(f"[AVISO]: Cuentas con contraseña VACÍA: {', '.join(cuentasVacias)}")
            for cuenta in cuentasVacias:
                print(f"[INFO]: Bloqueando cuenta sin contraseña: {cuenta}")
                ejecutar_comando(["passwd", "-l", cuenta], f"bloquear cuenta {cuenta}", "Paso 11")
                print(f"[CORRECTO]: {cuenta} bloqueada.")
        else:
            print("[CORRECTO]: No hay cuentas con contraseña vacía.")
    else:
        print(f"[ERROR]: No se pudo leer {SHADOW_FILE}.")

    resultado=subprocess.run(["passwd", "-S", "root"], capture_output=True, text=True)

    if resultado.returncode==0:
        campos=resultado.stdout.split()
        if len(campos)>=2 and campos[1]!="L":
            print("[INFO]: Bloqueando cuenta root. Se permitirá solo el acceso mediante sudo.")
            ejecutar_comando(["passwd", "-l", "root"], "bloquear root", "Paso 11")
            print("[CORRECTO]: Cuenta root bloqueada.")
        else:
            print("[INFO]: Cuenta root ya está bloqueada.")
    
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
                        print(f"[INFO]: Cambiando shell de cuenta de servicio: {usuario} ({shell}->/usr/sbin/nologin)...")
                        ejecutar_comando(["usermod", "-s", "/usr/bin/nologin", usuario], f"cambiar shell de {usuario}", "Paso 11")
                        print(f"[CORRECTO]: El usuario {usuario} ya no puede iniciar sesión.")
        
    print()
    print("[CORRECTO]: PASO 11 completado. Contraseñas y cuentas aseguradas.")
    print("            No hay cuentas con contraseña vacía.")
    print("            Root bloqueado. Acceso solo mediante sudo.")
    print("            Cuentas de servicio sin shell interactiva.")


def mostrar_menu():
    print()
    print("="*100)
    print("MÓDULO 2: Hardening General del Sistema Operativo - Ubuntu Server 24.04")
    print("="*100)
    print()
    print("Pasos disponibles:")
    print("1. Personalizar MOTD")
    print("2. Configurar banners de inicio de sesión")
    print("3. Eliminar paquetes innecesarios")
    print("4. Actualizar kernel y sistema")
    print("5. Verificación de integridad de paquetes (GPG)")
    print("6. Actualizaciones automáticas de seguridad")
    print("7. Deshabilitar servicios innecesarios")
    print("8. Documentar servicios autorizados")
    print("9. Habilitar NTP/Chronyd")
    print("10. Restringir cronjobs")
    print("11. Asegurar contraseñas y cuentas")
    print()
    print("q. Salir")
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
                print("\n[INFO]: Saliendo del script.")
                sys.exit(0)
            case _:
                print("[ERROR]: Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()

