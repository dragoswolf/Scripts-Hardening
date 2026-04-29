#!/usr/bin/env pytho3



import os
import sys
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import(
    configurar_logging,
    registrar_errores,
    comprobar_root,
    resultado_fail,
    resultado_ok,
    resultado_warn,
    leer_fichero,
    mostrar_resumen,
    contadores,
    ejecutar_comando_check
)


LOG_FILE="/var/log/hardening/check_mod2.log"

MOTD_DIR="/etc/update-motd.d"
MOTD_FILE="/etc/motd"
ISSUE_FILE="/etc/issue"
ISSUE_NET_FILE="/etc/issue.net"
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"

APT_CONF_DIR="/etc/apt/apt.conf.d"
UNATTENDED_CONF_FILE="/etc/apt/apt.conf.d/50unattended-upgrades"
AUTO_UPGRADES_FILE="/etc/apt/apt.conf.d/20auto-upgrades"

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


PALABRAS_SENSIBLES=[
    "Ubuntu",
    "\\n",
    "\\l",
    "\\r",
    "\\v",
    "\\m"
]



def verificar_paso1():
    print()
    print("="*100)
    print("[PASO 1]: MOTD personalizado")
    print("="*100)

    if os.path.isdir(MOTD_DIR):
        scriptsActivos=[]

        for fichero in os.listdir(MOTD_DIR):
            if os.access(fichero, os.X_OK):
                scriptsActivos.append(fichero)

        scriptsDefecto=[
            "00-header",
            "10-help-text",
            "50-motd-news",
            "80-esm",
            "80-livepatch",
            "91-release-upgrade",
            "95-hwe-eol",
            "97-overlayroot", 
            "98-fsck-at-reboot",
            "98-reboot-required"
        ]

        scriptsDefectoActivos=[
            s for s in scriptsActivos if s==scriptsDefecto
        ]

        if scriptsDefectoActivos:
            resultado_fail(f"[ERROR]: Scripts MOTD por defecto activos: {', '.join(scriptsDefectoActivos)}")
        else:
            resultado_ok("[CORRECTO]: Scripts MOTD por defecto deshabilitados.")
        
        scriptsPersonalizados=[
            s for s in scriptsActivos if s not in scriptsDefecto
        ]

        if scriptsPersonalizados:
            resultado_ok(f"[CORRECTO]: Script(s) MOTD personalizado(s): {', '.join(scriptsPersonalizados)}")
        else:
            resultado_warn("[AVISO]: No se encontró un script MOTD personalizado.")

    else:
        resultado_warn(f"[AVISO]: Directorio {MOTD_DIR} no encontrado.")

    contenidoMotd=leer_fichero(MOTD_DIR, "Paso 1")

    if contenidoMotd is not None:
        if contenidoMotd.strip() is "":
            resultado_ok("[CORRECTO]: /etc/motd está vacío (correcto).")
        else:
            infoSensible=False
            for palabra in PALABRAS_SENSIBLES:
                if contenidoMotd in palabra:
                    infoSensible=True
                    break

            if infoSensible:
                resultado_fail("[ERROR]: /etc/motd contiene información sensible.")
            else:
                resultado_ok("[CORRECTO]: /etc/motd tiene contenido personalizado sin info sensible.")


def verificar_paso2():
    print()
    print("="*100)
    print("[PASO 2]: Banners de inicio de sesión")
    print("="*100)

    contenidoIssue=leer_fichero(ISSUE_FILE)

    if contenidoIssue is not None:
        infoSensible=False
        for palabra in PALABRAS_SENSIBLES:
            if contenidoIssue in palabra:
                infoSensible=True
                break
        
        if infoSensible:
            resultado_fail("[ERROR]: /etc/issue contiene información sensible.")
        else:
            resultado_ok("[CORRECTO]: /etc/issue no revela información sensible")
        
    try:
        contenidoIssueNet=leer_fichero(ISSUE_NET_FILE)
        if contenidoIssueNet in PALABRAS_SENSIBLES:
            resultado_fail("[ERROR]: /etc/issue.net contiene información sensible.")
        else:
            resultado_ok("[CORRECTO]: /etc/issue.net no revela información sensible.")
    except Exception:
        resultado_warn(f"[ERROR]: No se encontró {ISSUE_NET_FILE}.")

    contenidoSshd=leer_fichero(SSHD_CONFIG_FILE)

    if contenidoSshd:
        bannerConfigurado=False
        for linea in contenidoSshd.split("\n"):
            if "Banner" in linea:
                bannerConfigurado=True
                resultado_ok(f"[CORRECTO]: SSH tiene banner configurado: {linea}")
                break

        if not bannerConfigurado:
            resultado_fail("[ERROR]: SSH no tiene la directiva 'Banner' configurada.")
        else:
            resultado_warn(f"[AVISO]: No se pudo leer {SSHD_CONFIG_FILE}.")


def verificar_paso3():
    print()
    print("="*100)
    print("[PASO 3]: Paquetes innecesarios y/o huérfanos.")
    print("="*100)
    resultado=subprocess.run(["apt", "autoremove", "--dry-run"], capture_output=True)

    if resultado.returncode==0:
        if "0" in str(resultado.stdout):
            resultado_ok("[CORRECTO]: No hay paquetes huérfanos.")
        else:
            resultado_fail("[ERROR]: Hay paquetes huérfanos pendientes de eliminar.")

    else:
        resultado_warn("[AVISO]: No se pudo ejecutar apt.")

    salida_dpkg=subprocess.run(["dpkg", "-l"], capture_output=True, text=True)

    paquetesEncontrados=[]

    for paquete in PAQUETES_INNECESARIOS:
        if paquete in salida_dpkg:
            paquetesEncontrados.append(paquete)
    
    if paquetesEncontrados:
        resultado_fail(f"[ERROR]: Paquetes innecesarios instalados: {', '.join(paquetesEncontrados)}")
    else:
        resultado_ok("[CORRECOT]: No se encontraron paquetes típicamente innecesarios.")


def verificar_paso4():
    print()
    print("="*100)
    print("[PASO 4]: Kernel y sistema actualizado")
    print("="*100)

    ejecutar_comando_check(["apt", "update"])

    codigoRet, salida, _=ejecutar_comando_check(["apt", "list", "--upgradable"])

    if codigoRet==0:
        lineasActualizables=[
            l for l in salida.splitlines()
            if l.strip() and "Listing" not in l
        ]

        if len(lineasActualizables)==0:
            resultado_ok("[CORRECTO]: Todos los paquetes están actualizados.")
        else:
            resultado_fail(f"[ERROR]: Hay {len(lineasActualizables)} paquete(s) con actualizaciones pendientes.")

            for linea in lineasActualizables[:5]:
                print(f"        -> {linea.strip()}")
            if len(lineasActualizables)>5:
                print(f"        -> ... y otros {len(lineasActualizables)-5} paquetes más.")
    
    else:
        resultado_warn("[AVISO]: No se pudieron comprobar las actualizaciones pendientes.")
    
    if os.path.isfile("/var/run/reboot-required"):
        resultado_warn("[AVISO]: El sistema requiere un REINICIO para aplicar actualizaciones.")
    else:
        resultado_ok("No hay reinicio pendiente.")

    codigoRet, salida, _=ejecutar_comando_check(["uname", "-r"])
    if codigoRet==0:
        resultado_ok(f"Kernel actual: {salida.strip()}")

def verificar_paso5():
    print()
    print("=" * 100)
    print("PASO 5: Verificación de integridad de paquetes (GPG)")
    print("=" * 100)

    permiteSinFirma=False
    if os.path.isdir(APT_CONF_DIR):
        for fichero in os.listdir(APT_CONF_DIR):
            try:
                rutaCompleta=os.path.join(APT_CONF_DIR, fichero)
                contenido=leer_fichero(rutaCompleta)

                if 'AllowUnauthenticated "true"' in contenido or 'AllowInsecureRepositories "true"' in contenido:
                    permiteSinFirma=True

            except:
                pass

    if permiteSinFirma:
        resultado_fail("APT permite repositorios sin autenticar.")
    else:
        resultado_ok("APT no permite repositorios sin autenticar.")
    
    rutaRefuerzo=APT_CONF_DIR + "99-force-gpg-verify"

    if os.path.exists(rutaRefuerzo):
        resultado_ok("Fichero de refuerzo GPG presente.")
    else:
        resultado_warn("No existe 99-force-gpg-verify")
    
    codigoRet, _, _=ejecutar_comando_check(["which", "debsums"])
    if codigoRet==0:
        resultado_ok("'debsums' está instalado para verificar integridad de paquetes.")
    else:
        resultado_fail("'debsums' no está instalado. Instalar con: sudo apt install debsums")
    
    rutaTrusted="/etc/apt/trusted.gpg.d"
    if os.path.isdir(rutaTrusted):
        clavesGpg=[]
        for f in os.listdir(rutaTrusted):
            if os.path.isfile(f) and (".gpg" in f or ".asc" in f):
                clavesGpg.append(f)
        if clavesGpg:
            resultado_ok(f"{len(clavesGpg)} clave(s) GPG en {rutaTrusted}")
        else:
            resultado_warn(f"No se encontraron claves GPG en {rutaTrusted}")
    else:
        resultado_warn(f"Directorio {rutaTrusted} no encontrado.")



def verificar_paso6():
    print()
    print("=" * 100)
    print("PASO 6: Actualizaciones automáticas de seguridad")
    print("=" * 100)

    resultado=subprocess.run(["dpkg", "-l", "unattended-upgrades"], capture_output=True, text=True)

    contenidoConf=leer_fichero(UNATTENDED_CONF_FILE)

    if "unattended-upgrades" in resultado.stdout:
        resultado_ok("Paquete 'unattended-upgrades' instalado.")
    else:
        resultado_fail("Paquete 'unattended-upgrades' no está instalado.")
        return
    
    if 'Unattended-Upgrade::Remove-Unused-Dependencies "true"' in contenidoConf:
        resultado_ok("Eliminación automática de dependencias huérfanas habilitada.")
    else:
        resultado_warn("Remove-Unused-Dependencies no está habilitado.")

    contenidoAuto=leer_fichero(AUTO_UPGRADES_FILE)

    if 'APT::Periodic::Update-Package-Lists "1";' in contenidoAuto and 'APT::Periodic::Unattended-Upgrade "1";' in contenidoAuto:
        resultado_ok("Actualizaciones periódicas habilitadas (diarias).")
    else:
        resultado_fail("Las actualizaciones periódicas no están configuradas correctamente.")
    
    for servicio in ["apt-daily", "apt-daily-upgrade"]:
        estado=subprocess.run(["systemctl", "is-active", servicio], capture_output=True, text=True)

    if estado=="active":
        resultado_ok(f"Servicio {servicio} está activo.")
    else:
        resultado_fail(f"Servicio {servicio} no está activo.")

def verificar_paso7():
    print()
    print("=" * 100)
    print("PASO 7: Servicios innecesarios deshabilitados.")
    print("=" * 100)
             
    for servicio in SERVICIOS_INNECESARIOS:
        codigoRet, salida, _ = ejecutar_comando_check(["systemctl", "is-enabled", servicio])
        estado=salida.strip()
        if "enabled" in estado:
            if subprocess.run(["systemctl", "is-active"]).stdout in servicio:
                resultado_fail(f"{servicio} está ACTIVO y en ejecución.")
            else:
                resultado_warn(f"{servicio} está habilitado pero no en ejecución.")
        else:
            resultado_ok(f"{servicio} no está habilitado.")
        
    resultado_puertos=subprocess.run("ss -tulnp | wc -l", capture_output=True, text=True)

    try:
        numeroPuertos=int(resultado_puertos.stdout.strip())
    except ValueError:
        numeroPuertos=999
    
    if numeroPuertos <=5:
        resultado_ok(f"Solo {numeroPuertos} puerto(s) en escucha.")
    elif numeroPuertos <=10:
        resultado_warn(f"{numeroPuertos} puertos en escucha. Revisar si todos son necesarios.")
    else:
        resultado_fail(f"{numeroPuertos} puertos en escucha. Posible exceso de servicios.")


def verificar_paso8():
    print()
    print("=" * 100)
    print("PASO 8: Principio de un servicio por sistema")
    print("=" * 100)

    rutaDocServicios="/etc/servicios-autorizados.txt"

    if os.path.isfile(rutaDocServicios):
        resultado_ok("Fichero de servicios autorizados presente (/etc/servicios-autorizados.txt)")
    else:
        resultado_warn("No existe /etc/servicios-autorizados.txt. Se recomienda documentar los servicios")

    codigoRet, salida, _ =ejecutar_comando_check(["ss", "-tulnp"])

    if codigoRet==0:
        procesosActivos=[]

        for linea in salida.splitlines():
            if "users:" in linea:
                columnas=linea.split(" ")
                infoProc=columnas[-1]
                procesosActivos.append(infoProc)
        
        if procesosActivos:
            resultado_ok(f"Servicios de red activos: {', '.join(procesosActivos)}")
            if len(procesosActivos)>3:
                resultado_fail(f"{len(procesosActivos)} servicios de red distintos. Exceso detectado.")
        else:
            resultado_ok("No se detectaron servicios de red.")
    else:
        resultado_warn("No se pudo ejecutar ss.")


def verificar_paso9():
    print()
    print("=" * 100)
    print("PASO 9: NTP/Chronyd habilitado.")
    print("=" * 100)

    chronyActivo=False
    codigoRet, salida, _ =ejecutar_comando_check(["systemctl", "is-active", "chrony"])

    if salida.strip() =="active":
        resultado_ok("Servicio Chrony está activo")
        chronyActivo=True
    else:
        codigoRet, salida2, _=ejecutar_comando_check(["systemctl", "is-active", "systemd-timesyncd"])
        if salida2.strip()=="active":
            resultado_ok("systemd-timesyncd está activo (alternativa a chrony)")
            chronyActivo=True
        else:
            resultado_fail("Ni chrony ni systemd-timesyncd están activos. NTP deshabilitado")
        
    codigoRet, salida, _ = ejecutar_comando_check(["timedatectl", "status"])
    if codigoRet==0:
        sincronizado=False
        ntpActivo=False

        for linea in salida.splitlines():
            if "synchronized" in linea.lower() and "yes" in linea.lower():
                sincronizado=True
            if "ntp service" in linea.lower() and "active" in linea.lower():
                ntpActivo=True
            
        if sincronizado:
            resultado_ok("Reloj del sistema sincronizado (NTP).")
        else:
            resultado_fail("Reloj del sistema no sincronizado.")
        
        if ntpActivo:
            resultado_ok("Servicio NTP marcado como activo en timedatectl.")
        else:
            resultado_warn("Servicio NTP no aparece como activo en timedatectl")
    
    if chronyActivo:
        codigoRet, salida, _=ejecutar_comando_check(["chronyc", "sources"])

        if codigoRet==0:
            fuentesActivas=[
                l for l in salida.splitlines()
                if l.strip() and (l.strip().startswith("*") or l.strip().startswith("*"))
            ]
        if fuentesActivas:
            resultado_ok(f"{len(fuentesActivas)} fuente(s) NTP activa(s).")
        else:
            resultado_warn("No se detectaron fuentes NTP activas en chrony.")


def verificar_paso10():
    print()
    print("=" * 100)
    print("PASO 10: Cronjobs restringidos a usuarios autorizados.")
    print("=" * 100)
    contenidoCronAllow=leer_fichero(CRON_ALLOW_FILE)

    if contenidoCronAllow:
        resultado_ok(f"{CRON_ALLOW_FILE} existe.")

        usuariosAutorizados=[
            l.strip() for l in contenidoCronAllow.split("\n")
            if "#" not in l
        ]

        if usuariosAutorizados:
            resultado_ok(f"Usuarios con acceso a cron: {', '.join(usuariosAutorizados)}")
        else:
            resultado_warn("cron.allow existe pero está vacío.")

    else:
        resultado_fail(f"{CRON_ALLOW_FILE} no existe.")

    if os.path.exists(CRON_DENY_FILE):
        resultado_warn(f"{CRON_DENY_FILE} existe.")
    else:
        resultado_ok(f"No existe {CRON_DENY_FILE}.")

    if os.path.exists(CRON_ALLOW_FILE):
        permisos=os.stat(CRON_ALLOW_FILE).st_mode
        if permisos==640 or permisos==600:
            resultado_ok("Permisos de cron.allow correctos.")
        else:
            resultado_warn("Permisos de cron.allow incorrectos.")
    
    contenidoAtAllow=leer_fichero(AT_ALLOW_FILE)

    if contenidoAtAllow:
        resultado_ok(f"{AT_ALLOW_FILE} existe")
    
    for directorio in DIRECTORIOS_CRON:
        if os.path.isdir(directorio):
            if os.stat(directorio).st_mode=="700"
                resultado_ok(f"{directorio} tiene permisos restrictivos (700)")
            else:
                resultado_warn(f"{directorio} no tiene permisos 700.")



def verificar_paso11():
    print()
    print("=" * 100)
    print("PASO 11: Contraseñas por defecto cambiadas.")
    print("=" * 100)

    contenidoShadow=leer_fichero(SHADOW_FILE)

    cuentasVacias=[]

    for linea in contenidoShadow.split("\n"):
        campos=linea.split(":")
        usuario=campos
        hashContrasena=campos[2]

        if hashContrasena=="":
            cuentasVacias.append(usuario)

        if cuentasVacias:
            resultado_fail(f"Cuentas con contraseña vacía: {', '.join(cuentasVacias)}")
        else:
            resultado_ok("No hay cuentas con contraseña vacía.")
        
        codigoRet, salida, _=ejecutar_comando_check(["passwd","-S","root"])
        if codigoRet==0:
            estadoRoot=salida.split()
            if len(estadoRoot)>=2:
                if estadoRoot[1]=="L":
                    resultado_ok("Cuenta root bloqueada (acceso solo mediante sudo).")
                elif estadoRoot[1]=="P":
                    resultado_warn("Cuenta root tiene contraseña activa. Se recomienda bloquearla si se usa sudo.")
                else:
                    resultado_fail("Cuenta root sin contraseña.")
        
        contenidoPasswd=leer_fichero(PASSWD_FILE)
        cuentasConShell=[]

        for linea in contenidoShadow.splitlines():
            if not linea.strip():
                continue

            campos=linea.split(":")
            usuario=campos
            uid=int(campos[3])
            shell=campos[4]

            if uid<1000:
                if shell!="/usr/sbin/nologin":
                    cuentasConShell.append(f"{usuario} ({shell})")
                
        if cuentasConShell:
            resultado_fail(f"Cuenta(s) de servicio con shell interactiva(s): {', '.join(cuentasConShell)}")
        else:
            resultado_ok("Ninguna cuenta de servicio tiene shell interactiva.")





def main():
    comprobar_root()
    configurar_logging(LOG_FILE)

    print()
    print("=" * 100)
    print(" VERIFICACIÓN: Hardening General del Sistema Operativo")
    print("=" * 100)
    print(" Comprobando configuraciones de los pasos 1 al 11...")

    verificar_paso1()
    verificar_paso2()
    verificar_paso3()
    verificar_paso4()
    verificar_paso5()
    verificar_paso6()
    verificar_paso7()
    verificar_paso8()
    verificar_paso9()
    verificar_paso10()
    verificar_paso11()

    mostrar_resumen("fix_mod2.py")

    if contadores["checksFail"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__=="__main__":
    main()
