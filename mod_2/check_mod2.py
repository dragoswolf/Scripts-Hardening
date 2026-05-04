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


SCRIPTS_DEFECTO=[
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


def verificar_paso1():
    print()
    print("="*100)
    print("[PASO 1]: MOTD personalizado")
    print("="*100)

    if os.path.isdir(MOTD_DIR):
        scriptsActivos=[]

        for fichero in os.listdir(MOTD_DIR):
            rutaCompleta=os.path.join(MOTD_DIR, fichero)
            if os.access(rutaCompleta, os.X_OK):
                scriptsActivos.append(fichero)

        scriptsDefectoActivos=[
            s for s in scriptsActivos if s in SCRIPTS_DEFECTO
        ]

        if scriptsDefectoActivos:
            resultado_fail(f"Scripts MOTD por defecto activos: {', '.join(scriptsDefectoActivos)}")
        else:
            resultado_ok("Scripts MOTD por defecto deshabilitados.")
        
        scriptsPersonalizados=[
            s for s in scriptsActivos if s not in SCRIPTS_DEFECTO
        ]

        if scriptsPersonalizados:
            resultado_ok(f"Script(s) MOTD personalizado(s): {', '.join(scriptsPersonalizados)}")
        else:
            resultado_warn("No se encontró un script MOTD personalizado.")

    else:
        resultado_warn(f"Directorio {MOTD_DIR} no encontrado.")

    contenidoMotd=leer_fichero(MOTD_FILE, "Paso 1")

    if contenidoMotd is not None:
        if contenidoMotd.strip() == "":
            resultado_ok("/etc/motd está vacío (correcto).")
        else:
            infoSensible=False
            for palabra in PALABRAS_SENSIBLES:
                if palabra in contenidoMotd:
                    infoSensible=True
                    break

            if infoSensible:
                resultado_fail("/etc/motd contiene información sensible.")
            else:
                resultado_ok("/etc/motd tiene contenido personalizado sin info sensible.")


def verificar_paso2():
    print()
    print("="*100)
    print("[PASO 2]: Banners de inicio de sesión")
    print("="*100)

    contenidoIssue=leer_fichero(ISSUE_FILE)

    if contenidoIssue is not None:
        infoSensible=False
        for palabra in PALABRAS_SENSIBLES:
            if palabra in contenidoIssue:
                infoSensible=True
                break
        
        if infoSensible:
            resultado_fail("/etc/issue contiene información sensible.")
        else:
            resultado_ok("/etc/issue no revela información sensible")
    else:
        resultado_warn(f"No se encontró {ISSUE_FILE}.")
        

    contenidoIssueNet=leer_fichero(ISSUE_NET_FILE)
    if contenidoIssueNet is not None:
        infoSensible=False
        for palabra in PALABRAS_SENSIBLES:
            if palabra in contenidoIssueNet:
                infoSensible=True
                break
        if infoSensible:
            resultado_fail("/etc/issue.net contiene información sensible.")
        else:
            resultado_ok("/etc/issue.net no revela información sensible.")
    else:
        resultado_warn(f"[ERROR]: No se encontró {ISSUE_NET_FILE}.")

    contenidoSshd=leer_fichero(SSHD_CONFIG_FILE)

    if contenidoSshd is not None:
        bannerConfigurado=False
        for linea in contenidoSshd.splitlines():
            lineaLimpia=linea.strip()
            if lineaLimpia.startswith("#"):
                continue
            if lineaLimpia.lower().startswith("banner"):
                bannerConfigurado=True
                resultado_ok(f"[CORRECTO]: SSH tiene banner configurado: {lineaLimpia}")
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
    
    codigoRet, salida, _ = ejecutar_comando_check(["apt", "autoremove", "--dry-run"])

    if codigoRet==0:
        for linea in salida.splitlines():
            lineaMin=linea.lower()
            if ("to remove" in lineaMin or "a eliminar" in lineaMin or "para eliminar" in lineaMin):
                if ("0 to remove" in lineaMin or "0 a eliminar" in linea or "0 para eliminar" in lineaMin):
                    resultado_ok("No hay paquetes huérfanos.")
                else:
                    resultado_fail(f"Hay paquetes huérfanos: {linea.strip()}")
                break
        else:
            if "The following packages will be REMOVED" in salida:
                resultado_fail("Hay paquetes huérfanos pendientes de eliminar.")
            else:
                resultado_ok("No hay paquetes huérfanos.")

    else:
        resultado_warn("No se pudo ejecutar apt autoremove --dry-run.")

    paquetesEncontrados=[]

    for paquete in PAQUETES_INNECESARIOS:
        codigoRet, salida, _=ejecutar_comando_check(["dpkg", "-l", paquete])
        if codigoRet==0 and f"ii  {paquete}" in salida:
            paquetesEncontrados.append(paquete)
    
    if paquetesEncontrados:
        resultado_fail(f"Paquetes innecesarios instalados: {', '.join(paquetesEncontrados)}")
    else:
        resultado_ok("No se encontraron paquetes típicamente innecesarios.")


def verificar_paso4():
    print()
    print("="*100)
    print("[PASO 4]: Kernel y sistema actualizado")
    print("="*100)

    print("[INFO]: Actualizando lista de paquetes...\n")
    ejecutar_comando_check(["apt", "update"], mostrarSalida=True)

    codigoRet, salida, _=ejecutar_comando_check(["apt", "list", "--upgradable"])

    if codigoRet==0:
        lineasActualizables=[
            l for l in salida.splitlines()
            if l.strip() and "Listing" not in l
        ]

        if len(lineasActualizables)==0:
            resultado_ok("Todos los paquetes están actualizados.")
        else:
            resultado_fail(f"Hay {len(lineasActualizables)} paquete(s) con actualizaciones pendientes.")

            for linea in lineasActualizables[:5]:
                print(f"        -> {linea.strip()}")
            if len(lineasActualizables)>5:
                print(f"        -> ... y otros {len(lineasActualizables)-5} paquetes más.")
    
    else:
        resultado_warn("No se pudieron comprobar las actualizaciones pendientes.")
    
    if os.path.isfile("/var/run/reboot-required"):
        resultado_warn("El sistema requiere un REINICIO para aplicar actualizaciones.")
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
            rutaCompleta=os.path.join(APT_CONF_DIR, fichero)
            contenido=leer_fichero(rutaCompleta)
            if contenido is not None:
                for linea in contenido.splitlines():
                    lineaLimpia=linea.strip()
                    if lineaLimpia.startswith("//"):
                        continue
                    if "allowunauthenticated" in lineaLimpia.lower():
                        if '"true"' in lineaLimpia.lower():
                            permiteSinFirma=True
                            break
                    if "allowinsecurerepositories" in lineaLimpia.lower():
                        if '"true"' in lineaLimpia.lower():
                            permiteSinFirma=True
                            break
 
    if permiteSinFirma:
        resultado_fail("APT permite repositorios sin autenticar.")
    else:
        resultado_ok("APT no permite repositorios sin autenticar.")
    
    rutaRefuerzo=os.path.join(APT_CONF_DIR, "99-force-gpg-verify")

    if os.path.exists(rutaRefuerzo):
        resultado_ok("Fichero de refuerzo GPG presente.")
    else:
        resultado_warn("No existe 99-force-gpg-verify. Se recomienda crear un refuerzo explícito.")
    
    codigoRet, _, _=ejecutar_comando_check(["which", "debsums"])
    if codigoRet==0:
        resultado_ok("'debsums' está instalado para verificar integridad de paquetes.")
    else:
        resultado_fail("'debsums' no está instalado. Instalar con: sudo apt install debsums")
    
    rutaTrusted="/etc/apt/trusted.gpg.d"
    if os.path.isdir(rutaTrusted):
        clavesGpg=[
            f for f in os.listdir(rutaTrusted)
            if f.endswith(".gpg") or f.endswith(".asc")
        ]

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

    codigoRet, salida, _ =ejecutar_comando_check(["dpkg", "-l", "unattended-upgrades"])

    if codigoRet==0 and "ii" in salida:
        resultado_ok("Paquete unattended-upgrades instalado.")
    else:
        resultado_fail("Paquete unattended-upgrades NO está instalado.")
        return

    contenidoConf=leer_fichero(UNATTENDED_CONF_FILE)
    if contenidoConf is not None:
        if "securit" in contenidoConf.lower():
            resultado_ok("Repositorios de seguridad configurados en unattended-upgrades.")
        else:
            resultado_fail("No se encontraron repositorios de seguridad en la configuración.")
    
        tieneAutoRemove=False
        for linea in contenidoConf.splitlines():
            lineaLimpia=linea.strip()
            if lineaLimpia.startswith("//"):
                continue
            if "remove-unused-dependencies" in lineaLimpia.lower():
                if '"true"' in lineaLimpia.lower():
                    tieneAutoRemove=True
                    break
        
        if tieneAutoRemove:
            resultado_ok("Eliminación automática de dependencias huérfanas habilitada.")
        else:
            resultado_warn("Remove-Unused-Dependencias no está habilitado (recomendado).")
    else:
        resultado_fail(f"No se encontró {UNATTENDED_CONF_FILE}.")

    contenidoAuto=leer_fichero(AUTO_UPGRADES_FILE)
    if contenidoAuto is not None:
        tieneUpdateList=False
        tieneUnattended=False
        for linea in contenidoAuto.splitlines():
            if "Update-Package-Lists" in linea and '"1"' in linea:
                tieneUpdateList=True
            if "Unattended-Upgrade" in linea and '"1"' in linea:
                tieneUnattended=True
        if tieneUnattended and tieneUpdateList:
            resultado_ok("Actualizaciones periódicas habilitadas.")
        else:
            resultado_fail("Las actualizaciones periódicas no están configuradas correctamente.")
    else:
        resultado_fail(f"No se encontró {AUTO_UPGRADES_FILE}.")
    
    for timer in ["apt-daily.timer", "apt-daily-upgrade.timer"]:
        codigoRet, salida, _=ejecutar_comando_check(["systemctl", "is-active", timer])
        if salida.strip()=="active":
            resultado_ok(f"Timer {timer} está activo.")
        else:
            resultado_fail(f"Timer {timer} NO está activo.")

def verificar_paso7():
    print()
    print("=" * 100)
    print("PASO 7: Servicios innecesarios deshabilitados.")
    print("=" * 100)
             
    for servicio in SERVICIOS_INNECESARIOS:
        codigoRet, salida, _ = ejecutar_comando_check(["systemctl", "is-enabled", servicio])
        estado=salida.strip()

        if estado=="masked":
            resultado_ok(f"{servicio} está enmascarado (máxima protección).")
        elif estado=="disabled":
            resultado_ok(f"{servicio} está deshabilitado.")
        elif estado in ("enabled", "static"):
            codigoRet2, salida2, _=ejecutar_comando_check(["systemctl", "is-active", servicio])
            if salida2.strip()=="active":
                resultado_fail(f"{servicio} está ACTIVO y corriendo.")
            else:
                resultado_warn(f"{servicio} está habilitado pero no corriendo.")
        elif "could not be found" in estado or codigoRet!=0:
            resultado_ok(f"{servicio} no está instalado en el sistema.")
        else:
            resultado_warn(f"{servicio} tiene estado desconocido: '{estado}'.")


    codigoRet, salida, _=ejecutar_comando_check(["ss", "-tulnp"])

    if codigoRet==0:
        lineasPuertos=[
            l for l in salida.splitlines()
            if l.strip() and "State" not in l
        ]

    numeroPuertos=len(lineasPuertos)
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
                inicio=linea.find("((")
                fin=linea.find("))")
                if inicio!=-1 and fin!=-1:
                    infoProc=linea[inicio +2:fin]
                    nombreProc=infoProc.split(",")[0].strip('"')
                    procesosActivos.add(nombreProc)
        
        if procesosActivos:
            resultado_ok(f"Servicios de red activos: {', '.join(sorted(procesosActivos))}")
            if len(procesosActivos)>3:
                resultado_warn(f"{len(procesosActivos)} servicios de red distintos." 
                               "Verificar que todos corresponden a la función del servidor.")
        else:
            resultado_ok("No se detectaron servicios de red.")


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

    if contenidoCronAllow is not None:
        resultado_ok(f"{CRON_ALLOW_FILE} existe.")

        usuariosAutorizados=[
            l.strip() for l in contenidoCronAllow.split("\n")
            if l.strip() and not l.strip().startswith("#")
        ]

        if usuariosAutorizados:
            resultado_ok(f"Usuarios con acceso a cron: {', '.join(usuariosAutorizados)}")
        else:
            resultado_warn("cron.allow existe pero está vacío.")

    else:
        resultado_fail(f"{CRON_ALLOW_FILE} no existe. Cualquier usuario puede crear cronjobs")

    if os.path.exists(CRON_DENY_FILE):
        if contenidoCronAllow is not None:
            resultado_warn(f"{CRON_DENY_FILE} existe pero es irrelevante (cron.allow) tiene prioridad).")
        else:
            resultado_warn(f"Solo existe {CRON_DENY_FILE}. Se recomienda usar cron.allow en su lugar.")
    else:
        if contenidoCronAllow is not None:
            resultado_ok(f"{CRON_DENY_FILE} no existe (correcto, cron.allow controla el acceso).")

    if os.path.exists(CRON_ALLOW_FILE):
        statInfo=os.stat(CRON_ALLOW_FILE)
        permisos=oct(statInfo.st_mode)[-3:]
        if permisos in ("640", "600"):
            resultado_ok(f"Permisos de cron.allow correctos: {permisos}")
        else:
            resultado_warn(f"Permisos de cron.allow: {permisos}. Recomendado: 640")
    
    contenidoAtAllow=leer_fichero(AT_ALLOW_FILE)

    if contenidoAtAllow:
        resultado_ok(f"{AT_ALLOW_FILE} existe")
    else:
        resultado_warn(f"{AT_ALLOW_FILE} no existe. Se recomienda restringir 'at' también.")
    
    for directorio in DIRECTORIOS_CRON:
        if os.path.isdir(directorio):
            statInfo=os.stat(directorio)
            permisos=oct(statInfo.st_mode)[-3:]
            if permisos=="700":
                resultado_ok(f"{directorio} tiene permisos restrictivos (700)")
            else:
                resultado_warn(f"{directorio} tiene permisos {permisos}. Recomendado: 700")



def verificar_paso11():
    print()
    print("=" * 100)
    print("PASO 11: Contraseñas por defecto cambiadas.")
    print("=" * 100)

    contenidoShadow=leer_fichero(SHADOW_FILE)

    if contenidoShadow is not None:
        cuentasVacias=[]
        for linea in contenidoShadow.splitlines():
            if not linea.strip():
                continue
        campos=linea.split(":")
        if len(campos)>=2:
            usuario=campos[0]
            hashContrasena=campos[1]
            if hashContrasena=="":
                cuentasVacias.append(usuario)

        if cuentasVacias:
            resultado_fail(f"Cuentas con contraseña vacía: {', '.join(cuentasVacias)}")
        else:
            resultado_ok("No hay cuentas con contraseña vacía.")
    else:
        resultado_fail(f"No se pudo leer {SHADOW_FILE}.")
        return
    
    codigoRet, salida, _=ejecutar_comando_check(["passwd", "-S", "root"])
    
    if codigoRet==0:
        campos=salida.split()
        if len(campos)>=2:
            estadoRoot=campos[1]
            if estadoRoot=="L":
                resultado_ok("Cuenta root bloqueada. Acceso únicamente mediante sudo.")
            elif estadoRoot=="P":
                resultado_warn("Cuenta root tiene contraseña activa." \
                "Se recomienda bloquearla si se usa sudo.")
            elif estadoRoot=="NP":
                resultado_fail("Cuenta root sin contraseña.")
    
    
        
    contenidoPasswd=leer_fichero(PASSWD_FILE)
    if contenidoPasswd is not None:
        cuentasConShell=[]
        
        for linea in contenidoShadow.splitlines():
            if not linea.strip():
                continue

            campos=linea.split(":")
            if len(campos)>=7:
                usuario=campos
                uid=int(campos[3])
                shell=campos[4]

                if uid>0 and uid<1000:
                    if "nologin" not in shell and "/false" not in shell and "sync" not in shell:
                        cuentasConShell.append(f"{usuario} ({shell})")
                
        if cuentasConShell:
            resultado_fail(f"Cuenta(s) de servicio con shell interactiva(s): "
                           f"{', '.join(cuentasConShell)}")
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
