#!/usr/bin/env python3
#=========================================================================================================
# fix_mod5.py - Script de fortificación para el módulo 5 - SSH (Secure Shell)
#=========================================================================================================
# Este script implementa las siguientes medidas de seguridad:
#
#   Paso 1: Cambiar el puerto SSH
#   Paso 2: Restringir acceso por usuarios (AllowUsers/DenyUsers)
#   Paso 3: Deshabilitar autenticación GSSAPI
#   Paso 4: Configurar LoginGraceTime
#   Paso 5: Configurar ClientAliveInterval y ClientAliveCountMax
#   Paso 6: Deshabilitar HostbasedAuthentication
#   Paso 7: Configurar IgnoreRhosts
#   Paso 8: Habilitar StrictModes
#   Paso 9: Deshabilitar PermitUserEnvironment
#   Paso 10: Habilitar PrintLastLog
#   Paso 11: Configurar Banner SSH
#   Paso 12: Deshabilitar contraseñas vacías en SSH
#   Paso 13: Deshabilitar login root por SSH
#   Paso 14: Configurar LogLevel
#   Paso 15: Configurar límites de conexión
#   Paso 16: Configurar algoritmos criptográficos
#
#
# IMPORTANTE: Este script debe ejecutarse como root (sudo)
#
# Los errores se registran en /var/log/hardening/modulo5_fix.log
#
# Autor: Dragos George Stan
# TFG: Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04
#=========================================================================================================

import os
import sys
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import (configurar_logging, 
                   registrar_errores, 
                   comprobar_root,
                   ejecutar_comando, 
                   ejecutar_comando_check, 
                   volver_al_menu,
                   escribir_fichero, 
                   leer_fichero,
                   print_info,
                   print_aviso,
                   print_correcto,
                   print_error 
                   )


#=========================================================================================================
# CONSTANTES
#=========================================================================================================

SSHD_CONFIG="/etc/ssh/sshd_config"
PASSWD="/etc/passwd"


LOG_FILE="/var/log/hardening/modulo5_fix.log"
#=========================================================================================================


#=========================================================================================================
# Funciones auxiliares
#=========================================================================================================
def configurar_directiva_ssh(directiva, valor, paso="General"):
    """
    Modifica o añade una directiva en sshd_config.

    Busca la directiva (activa o comentada). Si la encuentra, la actualiza.
    Si no la encuentra, la añade al final del fichero.

    Args:
        directiva (str): Nombre de la directiva SSH
        valor (str): Valor a establecer
        paso (str): Identificador del paso para el log
    
    Return:
        bool: True si se configuró correctamente, False en caso de error.
    """
    contenido=leer_fichero(SSHD_CONFIG, paso=paso)
    if contenido is None:
        registrar_errores(paso, f"No se pudo leer {SSHD_CONFIG}")
        return False
    
    lineas=contenido.splitlines()
    encontrado=False
    modificado=False

    for i, linea in enumerate(lineas):
        limpia=linea.strip()
        # Buscar la directiva activa o comentada
        # Patrón: opcionalmente # al inicio, luego directiva, y espacio
        if re.match(rf"^#?\s*{directiva}\s", limpia, re.IGNORECASE):
            # Extraer el valor actual
            partes=limpia.lstrip("# ").split(None, 1)
            valorActual=partes[1] if len(partes)>=2 else "(sin valor)"

            if limpia.startswith("#") or valorActual!=valor:
                lineas[i]=f"{directiva} {valor}"
                print_info(f"{directiva}: {valorActual} -> {valor}")
                modificado=True
            else:
                print_correcto(f"{directiva} ya tiene el valor correcto ({valor})")
            encontrado=True
            break

    if not encontrado:
        lineas.append(f"{directiva} {valor}")
        print_info(f"{directiva} {valor} añadido al final.")
        modificado=True

    if modificado:
        nuevoContenido="\n".join(lineas)

        if not nuevoContenido.endswith("\n"):
            nuevoContenido+="\n"

        return escribir_fichero(SSHD_CONFIG, nuevoContenido, permisos=0o600, paso=paso)
    
    return True

def recargar_ssh(paso="General"):
    """
    Valida la configuración SSH y recarga el servicio.

    Primero ejecuta 'sshd -t' para verificar que la configuración es válida.
    Solo si la validación es exitosa, recarga el servicio con systemctl.

    Args:
        paso (str): Identificador del paso para el log.

    Return:
        bool: True si se recargó correctamente, False en caso de error.
    """

    # Se valida la configuración antes de recargar
    rc,_,stderr=ejecutar_comando_check(["sshd", "-t"])

    if rc!=0:
        registrar_errores(paso, f"Configuración SSH inválida: {stderr.strip()}")
        print_error(f"La configuración de SSH no es válida:")
        print(f"         {stderr.strip()}")
        print_error("No se ha recargado el servicio.")
        # Muestra cada línea de error
        for lineaError in stderr.strip().splitlines():
            print(f"        {lineaError}")
            # Intenta extraer el número de línea para mostrar contexto
            # Formato típico: "/etc/ssh/sshd_config line 42:..."
            match=re.search(r"line (\d+)", lineaError)
            if match:
                numLinea=int(match.group(1))
                contenido=leer_fichero(SSHD_CONFIG, paso=paso)
                if contenido:
                    lineas=contenido.splitlines()
                    # Mostrar 2 líneas antes y después para dar contexto
                    inicio=max(0,numLinea-3)
                    fin=min(len(lineas), numLinea+2)
                    print()
                    for i in range(inicio, fin):
                        marca=" >>>" if i==numLinea-1 else "    "
                        print(f"        {marca} {i+1}: {lineas[i]}")
        return False
    
    # Recargar el servicio SSH
    ejecutar_comando(["systemctl", "reload", "ssh"], "recargar servicio SSH", paso)

    print_correcto("Servicio SSH recargado correctamente.")
    return True
#=========================================================================================================


# Medidas de seguridad
def paso1_cambiar_puertos():
    """
    Cambia el puerto de escucha de SSH a un puerto no estándar.
    Pide al usuario el nuevo puerto y valida que esté en rango.
    """
    print()
    print("="*100)
    print("[PASO 1]: Cambiar el puerto SSH.")
    print("="*100)
    print_info("Cambia el puerto de escucha de SSH a un puerto no estándar. Se pide el nuevo puerto y valida que esté en rango.")
    print()

    paso="Paso 1"

    # 1a. Comprueba si SSH está instalado, de lo contrario, lo instala
    if not os.path.isfile(SSHD_CONFIG):
        print_info("OpenSSH Server no está instalado. Instalando...")
        if not ejecutar_comando(["apt", "install", "-y", "openssh-server"], "instalar openssh-server", paso, mostrarSalida=True):
            if not os.path.isfile(SSHD_CONFIG):
                print_error("No se pudo instalar OpenSSH server.")
                return
        else:
            print_correcto("OpenSSH server instalado correctamente. Inicializando el demonio...")
            if ejecutar_comando(["systemctl", "start", "ssh"], "instalar servicio SSH", paso):
                print_correcto("Servicio SSH inicializado correctamente.")
            else:
                print_error("Error al iniciar el servicio SSH.")
            print()

    # 1b. Mostrar el puerto actual
    contenido=leer_fichero(SSHD_CONFIG, paso=paso)
    if contenido is None:
        registrar_errores(paso, f"No se pudo leer {SSHD_CONFIG}.")
        return
    
    puertoActual="22"
    lineas=contenido.splitlines()
    for linea in lineas:
        limpia=linea.strip()
        if limpia.startswith("Port ") and not limpia.startswith("#"):
            puertoActual=limpia.split()[1]
            break

    print_info(f"Puerto actual: {puertoActual}")
    print()
    print_info("Recomendaciones:")
    print_info("        - Usar un puerto entre 1024 y 65535")
    print_info("        - Evitar puertos conocidos (80, 443, 8080, 3306...)")
    print_info("        - Ejemplo: 2222, 2022, 49152")
    print()

    nuevoPuerto=input("Introduce el nuevo puerto SSH (o Enter para mantener el actual): ").strip()

    if not nuevoPuerto:
        print_info("No se realizaron cambios.")
        return
    
    try:
        puerto=int(nuevoPuerto)
    except ValueError:
        print_error("El puerto debe ser un número.")
        return
    
    if puerto < 1024 or puerto >65535:
        print_error("El puerto debe estar entre 1024 y 65535.")
        return
    
    if puerto==int(puertoActual):
        print_correcto(f"El puerto ya es {puerto}.")
        return
    
    # 1b. Validar y aplicar el nuevo puerto
    rc, salida, _=ejecutar_comando_check(["ss", "-tlnp", f"sport = :{puerto}"])

    if salida.strip().count("\n")>0:
        print_aviso(f"El puerto {puerto} parece estar en uso:")
        print(f"         {salida.strip()}")
        respuesta=input("¿Continuar de todas formas? (s/n): ").strip().lower()
        if respuesta!="s":
            print_info("No se realizaron cambios.")
            return
        
    if configurar_directiva_ssh("Port", str(puerto), paso):
        recargar_ssh(paso)
        print()
        print_info(f"Recuerda conectarte con: ssh -p {puerto} usuario@servidor")
        print_info(f"Actualiza las reglas del firewall si es necesario.")


def paso2_allow_users():
    """
    Configura AllowUsers para restringir qué usuarios pueden conectarse por SSH
    """
    print()
    print("="*100)
    print("[PASO 2]: Restringir acceso por usuarios.")
    print("="*100)
    print_info("Configura AllowUsers para restringir qué usuarios pueden conectarse por SSH.")
    print()

    paso="Paso 2"

    # 2a. Mostrar configuración actual de AllowUsers
    contenido=leer_fichero(SSHD_CONFIG, paso=paso)
    if contenido is None:
        registrar_errores(paso, f"No se pudo leer {SSHD_CONFIG}.")
        return
    
    allowActual=None
    lineas=contenido.splitlines()

    for linea in lineas:
        limpia=linea.strip()
        if limpia.startswith("AllowUsers ") and not limpia.startswith("#"):
            allowActual=limpia.split(None, 1)[1]
            break

    if allowActual:
        print_info(f"AllowUsers actual: {allowActual}")
    else:
        print_info("AllowUsers no está configurado (todos los usuarios pueden conectarse).")

    contenidoPasswd=leer_fichero(PASSWD, paso)
    if contenidoPasswd:
        usuariosHumanos=[]
        lineas=contenidoPasswd.strip().splitlines()
        for linea in lineas:
            campos=linea.split(":")
            if len(campos)==7:
                uid=int(campos[2])
            
                if 1000<=uid<65535:
                    usuariosHumanos.append(campos[0])
        if usuariosHumanos:
            print()
            print_info(f"Usuarios humanos del sistema: {', '.join(usuariosHumanos)}")

    print()
    print_aviso("Si no incluyes tu usuario, perderás acceso SSH.")
    print_info("Introduce los usuarios separados por espacios.")
    print("        Ejemplo: usuario1 usuario2 usuario3...")
    print()

    usuarios=input("Usuarios permitidos (o Enter para no cambiar): ").strip()

    if not usuarios:
        print_info("No se realizaron cambios.")
        return
    
    # 2b. Validar usuarios y aplicar AllowUsers
    listaUsuarios=usuarios.split()

    for usuario in listaUsuarios:
        rc,_,_=ejecutar_comando_check(["id", usuario])
        if rc !=0:
            print_aviso(f"El usuario '{usuario}' no existe en el sistema.")
            respuesta=input("¿Continuar de todas formas? (s/n): ").strip().lower()
            if respuesta!="s":
                print_info("No se realizaron cambios.")
                return

    if configurar_directiva_ssh("AllowUsers", " ".join(listaUsuarios), paso):
        recargar_ssh(paso)

def paso3_deshabilitar_gssapi():
    """
    Deshabilita la autenticación GSSAPI en SSH para reducir la superficie de ataque
    y acelerar la conexión SSH
    """
    print()
    print("="*100)
    print("[PASO 3]: Deshabilitar autenticación GSSAPI.")
    print("="*100)
    print_info("Deshabilita la autenticación GSSAPI (Kerberos).")
    print()

    paso="Paso 3"

    if configurar_directiva_ssh("GSSAPIAuthentication", "no", paso):
        recargar_ssh(paso)

    
def paso4_login_grace_time():
    """
    Configura LoginGraceTime a 30 segundos.
    """
    print()
    print("="*100)
    print("[PASO 4]: Configurar LoginGraceTime.")
    print("="*100)
    print_info("Limita a 30 segundos el tiempo para completar la autenticación SSH.")
    print()

    paso="Paso 4"

    print_info("LoginGraceTime limita el tiempo para autenticarse.")
    print_info("Valor recomendado: 30 segundos.")
    print()

    if configurar_directiva_ssh("LoginGraceTime", "30", paso):
        recargar_ssh(paso)



def paso5_client_alive():
    """
    Configura el timeout de sesiones SSH inactivas.
    """
    print()
    print("="*100)
    print("[PASO 5]: Configurar ClientAliveInterval y ClientAliveCountMax.")
    print("="*100)
    print_info("Configura el timeout de sesiones SSH inactivas.")
    print()

    paso="Paso 5"

    print_info("Configuración de timeout de sesiones inactivas:")
    print_info("         - ClientAliveInterval = 300 segundos")
    print_info("         - ClientAliveCountMax = 3 segundos")
    print_info("         - Timeout total: 300 x 3 = 900 segundos")
    print()

    exito1=configurar_directiva_ssh("ClientAliveInterval", "300", paso)
    exito2=configurar_directiva_ssh("ClientAliveCountMax", "3", paso)

    if exito1 and exito2:
        recargar_ssh(paso)


def paso6_hostbased_auth():
    """
    Deshabilita la autenticación basada en host. Esto permite acceso sin verificar
    la identidad individual del usuario. Si un host se comrpomete, todos sus usuarios
    tendrían acceso.
    """
    print()
    print("="*100)
    print("[PASO 6]: Deshabilitar HostbasedAuthentication")
    print("="*100)
    print_info("Deshabilita la autenticación basada en host.")
    print()

    paso="Paso 6"

    if configurar_directiva_ssh("HostbasedAuthentication", "no", paso):
        recargar_ssh(paso)


def paso7_ignore_rhosts():
    """
    Configura SSH para ignorar ficheros .rhosts y .shosts, evitando relaciones de confianza
    heredadas de rlogin que un atacante podría explotar.
    """
    print()
    print("="*100)
    print("[PASO 7]: Configurar ClientAliveInterval y ClientAliveCountMax.")
    print("="*100)
    print_info("Configura SSH para ignorar ficheros .rhosts y .shosts")
    print()

    paso="Paso 7"

    if configurar_directiva_ssh("IgnoreRhosts", "yes", paso):
        recargar_ssh(paso)


def paso8_strict_modes():
    """
    Habilita StrictModes para verificar permisos de ficheros SSH
    """
    print()
    print("="*100)
    print("[PASO 8]: Habilitar StrictModes")
    print("="*100)
    print_info("Habilita StrictModes para que SSH verifique los permisos antes de permitir la autenticación por clave.")
    print()

    paso="Paso 8"

    if configurar_directiva_ssh("StrictModes", "yes", paso):
        recargar_ssh(paso)


def paso9_permit_user_environment():
    """
    Deshabilita la capacidad de los usuarios de establecer variables de entorno a través de SSH
    """
    print()
    print("="*100)
    print("[PASO 9]: Deshabilitar PermitUserEnvironment")
    print("="*100)
    print_info("Impide que los usuarios definan variables de entorno via SSH.")
    print()

    paso="Paso 9"

    if configurar_directiva_ssh("PermitUserEnvironment", "no", paso):
        recargar_ssh(paso)


def paso10_print_last_log():
    """
    Habilita PrintLastLog para mostrar la última conexión al hacer login,
    permitiendo detectar accesos no autorizados a su cuenta.
    """
    print()
    print("="*100)
    print("[PASO 10]: Habilitar PrintLastLog")
    print("="*100)
    print_info("Muestra al usuario la fecha, hora e IP de su última conexión SSH.")
    print()

    paso="Paso 10"

    if configurar_directiva_ssh("PrintLastLog", "yes", paso):
        recargar_ssh(paso)


def paso11_banner_ssh():
    """
    Configura la directiva Banner en sshd_config para que SSH muestre
    el contenido de /etc/issue.net a los usuarios antes de autenticarse
    """
    print()
    print("="*100)
    print("[PASO 11]: Configurar Banner SSH")
    print("="*100)
    print_info("Configurar el banner SSH para mostrar a la hora de\n" \
    "autenticarse.")
    print()

    paso="Paso 11"

    # 11a. Verificar que /etc/issue.net existe
    if not os.path.isfile("/etc/issue.net"):
        print_aviso("El fichero /etc/issue.net no existe.")
        print_aviso("Ejecuta primero el módulo 2, paso 2 para\n" \
        "crear el banner con el texto de aviso legal.")
        return

    # 11b. Configurar la directiva Banner
    if configurar_directiva_ssh("Banner", "/etc/issue.net", paso):
        recargar_ssh(paso)

def paso12_permit_emtpy_passwords():
    """
    Configura PermitEmptyPasswords para impedir el login SSH con cuentas sin contraseña.
    """
    print()
    print("="*100)
    print("[PASO 12]: Deshabilitar contraseñas vacías en SSH.")
    print("="*100)
    print_info("Impide que los usuarios con contraseña vacía puedan\n" \
    "       conectarse por SSH.")
    print()

    paso="Paso 12"

    if configurar_directiva_ssh("PermitEmptyPasswords","no", paso):
        recargar_ssh(paso)


def paso13_permit_root_login():
    """
    Configura PermitRootLogin para impedir el acceso directo como root por SSH
    """
    print()
    print("="*100)
    print("[PASO 13]: Deshabilitar login root por SSH.")
    print("="*100)
    print_info("Impide el acceso directo como root por SSH.\n" \
    "       Los administradores deben conectarse con su cuenta personal\n" \
    "       y usar sudo para tareas de root.")
    print()

    paso="Paso 13"

    if configurar_directiva_ssh("PermitRootLogin", "no", paso):
        recargar_ssh(paso)


def paso14_log_level():
    """
    Configura LogLevel a INFO para registrar eventos de autenticación
    """
    print()
    print("="*100)
    print("[PASO 14]: Deshabilitar login root por SSH.")
    print("="*100)
    print_info("Establece el nivel de log de SSH a INFO para registrar eventos de\n" \
    "       autenticación en los logs del sistema.")
    print()

    paso="Paso 14"

    if configurar_directiva_ssh("LogLevel", "INFO", paso):
        recargar_ssh(paso)


def paso15_limites_conexion():
    """
    Configura MaxAuthTries, MaxSessions y MaxStartups para limitar intentos de 
    autenticación y conexiones simultáneas
    """
    print()
    print("="*100)
    print("[PASO 15]: Configurar límites de conexión.")
    print("="*100)
    print_info("Limita los intentos de autenticación, sesiones simultáneas y\n" \
    "       conexiones pendientes de autenticar para reducir la efectividad" \
    "       de ataques de fuerza bruta.")
    print()

    paso="Paso 15"

    correctos=0

    # 15a. MaxAuthTries
    print_info("Máximo de intentos de autenticación por conexión. (MaxAuthTries)")
    if configurar_directiva_ssh("MaxAuthTries", "4", paso):
        print_correcto("MaxAuthTries configurado.")
        correctos+=1
    
    # 15b. MaxSessions
    print_info("Máximo de sesiones multiplexadas por conexión. (MaxSessions)")
    if configurar_directiva_ssh("MaxSessions", "10", paso):
        print_correcto("MaxSessions configurado.")
        correctos+=1

    # 15c. MaxStartups
    print_info("Límite de conexiones sin autenticar. (MaxStartups)")
    if configurar_directiva_ssh("MaxStartups", "10:30:60", paso):
        print_correcto("MaxStartups configurado.")
        correctos+=1
    
    if correctos==3:
        recargar_ssh(paso)


def paso16_algoritmos_criptograficos():
    """
    "Configura los algoritmos de cifrado, intercambio de claves y MACs permitidos,
    descartando los considerados débiles u obsoletos.
    """
    print()
    print("="*100)
    print("[PASO 16]: Configurar algoritmos criptográficos.")
    print("="*100)
    print_info("Restringe los algoritmos criptográficos de SSH a los\n" \
    "       considerados seguros, descartando cifrados débiles.")
    print()

    paso="Paso 16"

    correctos=0

    # 16a. Cifrados simétricos
    print_info("Configurando cifrados simétricos permitidos...")
    ciphers=",".join([
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com"
    ])
    if configurar_directiva_ssh("Ciphers", ciphers, paso):
        print_correcto("Algoritmos de cifrado simétrico configurados.")
        correctos+=1

    # 16b. Algoritmos de intercambio de claves
    print_info("Configurando algoritmos de intercambio de claves...")
    kex=",".join([
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group-exchange-sha256",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
    ])
    if configurar_directiva_ssh("KexAlgorithms", kex, paso):
        print_correcto("Algoritmos de intercambio de claves configurados.")
        correctos+=1


    # 16c. Algoritmos de integridad
    print_info("Configurando algoritmos de integridad...")
    macs=",".join([
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "umac-128-etm@openssh.com",
        "umac-128@openssh.com"
    ])
    if configurar_directiva_ssh("MACs", macs, paso):
        print_correcto("Algoritmos de integridad configurados.")
        correctos+=1
    
    if correctos==3:
        recargar_ssh(paso)
    print()



        
def mostar_menu():
    print()
    print("="*100)
    print("Hardening: Conexiones SSH (Secure Shell)")
    print("="*100)
    print()
    print(" Pasos disponibles:")
    print("     1. Cambiar el puerto SSH")
    print("     2. Restringir acceso por usuarios (AllowUsers)")
    print("     3. Deshabilitar autenticación GSSAPI")
    print("     4. Configurar LoginGraceTime (30s)")
    print("     5. Configurar ClientAliveInterval y ClientAliveCountMax")
    print("     6. Deshabilitar HostbasedAuthentication")
    print("     7. Configurar IgnoreRhosts")
    print("     8. Habilitar StrictModes")
    print("     9. Deshabilitar PermitUserEnvironment")
    print("     10. Habilitar PrintLastLog")
    print("     11. Configurar Banner SSH")
    print("     12. Deshabilitar contraseñas vacías en SSH")
    print("     13. Deshabilitar login root por SSH")
    print("     14. Configurar LogLevel")
    print("     15. Configurar límites de conexión")
    print("     16. Configurar algoritmos criptográficos.")
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
                paso1_cambiar_puertos()
                volver_al_menu()
            case "2":
                paso2_allow_users()
                volver_al_menu()
            case "3":
                paso3_deshabilitar_gssapi()
                volver_al_menu()
            case "4":
                paso4_login_grace_time()
                volver_al_menu()
            case "5":
                paso5_client_alive()
                volver_al_menu()
            case "6":
                paso6_hostbased_auth()
                volver_al_menu()
            case "7":
                paso7_ignore_rhosts()
                volver_al_menu()
            case "8":
                paso8_strict_modes()
                volver_al_menu()
            case "9":
                paso9_permit_user_environment()
                volver_al_menu()
            case "10":
                paso10_print_last_log()
                volver_al_menu()
            case "11":
                paso11_banner_ssh()
                volver_al_menu()
            case "12":
                paso12_permit_emtpy_passwords()
                volver_al_menu()
            case "13":
                paso13_permit_root_login()
                volver_al_menu()
            case "14":
                paso14_log_level()
                volver_al_menu()
            case "15":
                paso15_limites_conexion()
                volver_al_menu()
            case "16":
                paso16_algoritmos_criptograficos()
                volver_al_menu()
            case "q":
                print_info("Saliendo del script.")
                sys.exit(0)
            case _:
                print_error("Opción no válida. Inténtelo de nuevo.")


if __name__=="__main__":
    main()
