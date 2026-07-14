# Hardening Integral — Ubuntu Server 24.04 LTS

| | |
|---|---|
| **Autor** | Dragos George Stan |
| **Trabajo** | Metodología técnica de fortificación integral automatizada para Ubuntu Server 24.04 |
| **Universidad** | Universidad Internacional de La Rioja (UNIR) |
| **Titulación** | Grado en Ingeniería Informática |
| **Fecha** | 14 Julio 2026 |

Herramienta automatizada de fortificación para Ubuntu Server 24.04 LTS, organizada en 14 módulos de seguridad independientes. Desarrollada íntegramente en Python utilizando solo bibliotecas estándar (`os`, `subprocess`), sin dependencias de terceros.

Cada módulo sigue un patrón consistente de corrección (fix) y verificación (check), accesible a través de un menú interactivo por línea de comandos. La herramienta proporciona retroalimentación en tiempo real mediante mensajes codificados por colores y registra automáticamente todos los errores en `/var/log/hardening/`, con un fichero de log independiente por módulo.

## Requisitos previos

- Ubuntu Server 24.04 LTS
- Privilegios de root (`sudo`)
- Python 3 (incluido con Ubuntu Server)

## Cómo ejecutar

Clona este repositorio y ejecuta el menú interactivo con privilegios de root:

```bash
git clone https://github.com/dragoswolf/Scripts-Hardening.git
cd Scripts-Hardening
sudo python3 menu_principal.py
```

El menú principal presenta los 14 módulos en orden secuencial. Selecciona un módulo introduciendo su número. Tras completar el script de corrección (fix), la herramienta preguntará si se desea ejecutar el script de verificación (check) del mismo módulo. Introduce `q` para salir.

## Módulos

### Módulo 1: Seguridad en acceso al hardware

Protege el proceso de arranque y restringe vectores de acceso físico. Establece una contraseña en GRUB para impedir modificaciones no autorizadas de los parámetros de arranque, deshabilita el reinicio mediante `Ctrl+Alt+Delete` vía systemd y bloquea los dispositivos de almacenamiento USB mediante la lista negra del módulo del kernel `usb-storage` a través de modprobe.

**Ficheros modificados:**
- Ficheros de configuración de GRUB (hash de contraseña GRUB)
- `ctrl-alt-del.target` de systemd (atajo de reinicio)
- `/etc/modprobe.d/` (lista negra de almacenamiento USB)

---

### Módulo 2: Hardening general del sistema

Aplica una fortificación base a nivel de todo el sistema. Personaliza el MOTD deshabilitando los scripts por defecto en `/etc/update-motd.d/` y reemplazándolos con un aviso legal. Configura banners de inicio de sesión en `/etc/issue` y `/etc/issue.net`. Elimina paquetes innecesarios, actualiza el kernel y el sistema, y verifica la integridad de los paquetes con GPG. Configura `unattended-upgrades` para actualizaciones de seguridad automáticas con notificaciones por correo y reinicio automático programado a las 3:00 AM. Deshabilita servicios innecesarios, habilita la sincronización NTP mediante `chrony`, restringe el acceso a crontab y asegura las cuentas y contraseñas por defecto.

**Ficheros modificados:**
- `/etc/update-motd.d/` (scripts MOTD)
- `/etc/issue` (banner de inicio de sesión local)
- `/etc/issue.net` (banner de inicio de sesión remoto)
- `/etc/apt/apt.conf.d/50unattended-upgrades` (configuración de actualizaciones automáticas)
- `/etc/apt/apt.conf.d/20auto-upgrades` (programación de actualizaciones automáticas)
- Configuración de chrony
- `/etc/cron.allow`, `/etc/cron.deny` (control de acceso a crontab)
- `/etc/passwd`, `/etc/shadow` (seguridad de cuentas)

---

### Módulo 3: Usuarios y grupos

Gestiona identidades y controles de privilegios. Audita los shells de las cuentas de servicio y los establece a `/usr/sbin/nologin`. Audita la pertenencia a grupos y revisa la configuración de sudo en busca de reglas `NOPASSWD` inseguras. Establece permisos y propietarios correctos en `/etc/passwd` y `/etc/shadow`. Configura políticas de caducidad de contraseñas en `/etc/login.defs` y las aplica a los usuarios existentes. Deshabilita cuentas sin contraseña, bloquea usuarios no root con UID 0, bloquea automáticamente cuentas inactivas tras 30 días, restringe el acceso directo a root y establece permisos de directorios home a `0750` y permisos de ficheros de inicialización del shell a `0640`.

**Ficheros modificados:**
- `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`
- `/etc/sudoers` y ficheros en `/etc/sudoers.d/`
- `/etc/login.defs` (políticas de caducidad de contraseñas)
- Directorios home de usuarios (permisos establecidos a `0750`)
- Ficheros de inicialización del shell: `.bashrc`, `.profile`, `.bash_logout`, etc. (permisos establecidos a `0640`)

---

### Módulo 4: PAM (Pluggable Authentication Modules)

Fortalece el sistema de autenticación. Elimina `nullok` de la configuración PAM para rechazar contraseñas vacías. Configura la complejidad de contraseñas en `/etc/security/pwquality.conf` (clases mínimas de caracteres, verificación de diccionario, verificación de nombre de usuario). Configura el bloqueo de cuentas mediante `pam_faillock.so` (5 intentos fallidos en 15 minutos, desbloqueo automático tras 10 minutos, aplica a root). Aplica historial de contraseñas (recuerda las últimas 5 contraseñas, usa hashing yescrypt/sha512). Configura permisos por defecto de ficheros (umask) y límites de recursos en `/etc/security/limits.conf` (procesos máximos, ficheros abiertos, volcados de memoria, memoria bloqueada).

**Ficheros modificados:**
- `/etc/pam.d/common-auth`
- `/etc/pam.d/common-password`
- `/etc/pam.d/common-account`
- `/etc/security/pwquality.conf` (reglas de complejidad de contraseñas)
- `/etc/security/limits.conf` (límites de recursos)

---

### Módulo 5: SSH (Secure Shell)

Fortalece el servicio SSH con 16 medidas de seguridad. Cambia el puerto SSH por defecto, configura la lista blanca `AllowUsers`, deshabilita la autenticación GSSAPI, establece `LoginGraceTime` a 30 segundos, configura los ajustes de keepalive del cliente (`ClientAliveInterval`/`ClientAliveCountMax`), deshabilita `HostbasedAuthentication`, habilita `IgnoreRhosts` y `StrictModes`, deshabilita `PermitUserEnvironment`, habilita `PrintLastLog`, configura el banner SSH vía `/etc/issue.net`, deshabilita la autenticación con contraseña vacía y el inicio de sesión de root, establece `LogLevel`, configura límites de conexión (`MaxAuthTries`, `MaxSessions`, `MaxStartups`) y aplica algoritmos criptográficos robustos (cifrados, intercambio de claves, MACs).

**Ficheros modificados:**
- `/etc/ssh/sshd_config` (todos los parámetros de fortificación SSH)
- `/etc/issue.net` (banner de inicio de sesión SSH)

---

### Módulo 6: Sistema de ficheros

Asegura el sistema de ficheros. Audita y deshabilita binarios SUID/SGID innecesarios comparándolos contra una lista blanca de Ubuntu 24.04. Realiza auditorías del sistema de ficheros en busca de directorios con escritura global, ficheros huérfanos y ficheros con lectura global. Configura opciones de montaje seguras en `/etc/fstab` (`noexec`, `nosuid`, `nodev` para `/tmp` y `/dev/shm`). Protege ficheros críticos con el atributo inmutable (`chattr +i` en `/etc/fstab`).

**Ficheros modificados:**
- `/etc/fstab` (opciones de montaje para `/tmp`, `/dev/shm`)
- Diversos binarios del sistema (eliminación de bits SUID/SGID)

---

### Módulo 7: Parámetros del kernel

Fortalece los parámetros del kernel mediante sysctl. Habilita SYN cookies, deshabilita el enrutamiento de origen, deshabilita las redirecciones ICMP (aceptar y enviar), habilita la protección contra errores ICMP, oculta las direcciones de punteros del kernel (`kptr_restrict`), habilita ASLR (`randomize_va_space`), registra paquetes marcianos, ignora las difusiones de eco ICMP y deshabilita IPv6.

**Ficheros modificados:**
- `/etc/sysctl.d/99-hardening.conf` (todos los parámetros de fortificación del kernel)

---

### Módulo 8: AppArmor (Control de acceso obligatorio)

Configura el control de acceso obligatorio. Verifica que AppArmor está instalado y activo (paquetes `apparmor`, `apparmor-utils`, servicio systemd, módulo del kernel). Instala perfiles adicionales de los paquetes `apparmor-profiles` y `apparmor-profiles-extra` (inicialmente en modo queja). Cambia todos los perfiles de modo queja a modo obligatorio.

**Ficheros modificados:**
- `/etc/apparmor.d/` (perfiles de AppArmor cambiados a modo obligatorio)

---

### Módulo 9: Firewall (UFW)

Configura el firewall UFW. Instala y activa UFW con valores por defecto seguros (denegar entrante, permitir saliente). Crea automáticamente una regla de permiso para SSH antes de activar el firewall (lee el puerto SSH real de `sshd_config` para evitar bloqueos). Verifica que la regla SSH persiste y habilita el registro del firewall a nivel bajo.

**Ficheros modificados:**
- Configuración y reglas de UFW (`/etc/ufw/`)

---

### Módulo 10: Configuración y supervisión de logs

Fortalece el registro del sistema. Verifica que Rsyslog está instalado y activo. Configura journald para almacenamiento persistente (`Storage=persistent` en `/etc/systemd/journald.conf`), crea `/var/log/journal/` con los permisos adecuados y establece límites de tamaño del journal. Asegura los permisos de los ficheros de log en `/var/log/`. Configura logrotate para los logs de rsyslog.

**Ficheros modificados:**
- `/etc/systemd/journald.conf` (registro persistente, límites de tamaño)
- `/var/log/journal/` (creado con permisos restringidos)
- `/var/log/` (permisos de ficheros fortificados)
- `/etc/logrotate.d/rsyslog` (configuración de rotación de logs)

---

### Módulo 11: Detección de intrusos de host (AIDE)

Implementa un sistema de detección de intrusos basado en host mediante AIDE (Advanced Intrusion Detection Environment). Instala los paquetes `aide` y `aide-common`, inicializa la base de datos de AIDE con hashes criptográficos del estado actual del sistema y programa una verificación automática diaria mediante cron. El script de cron ejecuta `aide --check` diariamente, compara el estado actual contra la base de datos de referencia y registra los resultados en `/var/log/aide/aide-check.log`. Si se detectan cambios, envía una alerta a syslog. Los códigos de retorno de AIDE indican el tipo de cambio (0 = sin cambios, 1-2-4 = ficheros añadidos/eliminados/modificados).

**Ficheros creados:**
- `/var/log/aide/aide-check.log` (resultados de verificación diaria)
- Script de cron para la ejecución diaria de `aide --check`

**Ficheros modificados:**
- Base de datos de AIDE (estado de referencia de los ficheros del sistema)

---

### Módulo 12: Antimalware

Despliega dos herramientas complementarias de detección de malware: ClamAV y RKHunter. Instala ClamAV (paquetes `clamav`, `clamav-daemon`) con el demonio freshclam para la actualización automática de firmas de virus. Configura ClamAV y crea un script semanal en cron (`cron.weekly`) que ejecuta un escaneo completo del sistema; si detecta ficheros infectados, envía una alerta a syslog. Instala RKHunter y genera una base de datos de propiedades del sistema con `rkhunter --propupd` que sirve como referencia para detectar rootkits. Configura RKHunter y crea un script semanal en cron (`cron.weekly`) que ejecuta escaneos periódicos, registrando las advertencias y enviando los hallazgos críticos a syslog.

**Ficheros creados:**
- `/etc/cron.weekly/` (script de escaneo semanal de ClamAV)
- `/etc/cron.weekly/` (script de escaneo semanal de RKHunter)
- Base de datos de propiedades de RKHunter (hashes de binarios del sistema como referencia)

**Ficheros modificados:**
- Configuración de ClamAV (freshclam, ajustes de escaneo)
- Configuración de RKHunter (ajustes de escaneo, base de datos de firmas)

---

### Módulo 13: Fail2Ban

Implementa un servicio de prevención de intrusiones que monitoriza los ficheros de log del sistema en tiempo real y banea automáticamente las direcciones IP que presenten comportamientos maliciosos. Instala Fail2Ban y verifica que UFW está activo (Fail2Ban utiliza UFW para crear las reglas de baneo). Configura una lista blanca de IPs de forma interactiva, solicitando al administrador las IPs o subredes que deben quedar exentas del baneo automático. Genera una configuración personalizada en `jail.local` (en lugar de `jail.conf` para evitar que las actualizaciones del paquete la sobrescriban) y habilita el jail de SSH. Habilita e inicia el servicio Fail2Ban en el arranque. Proporciona un menú interactivo para gestionar la lista blanca de IPs tras la configuración inicial sin necesidad de reconfigurar todo el servicio.

**Ficheros creados:**
- `/etc/fail2ban/jail.local` (configuración personalizada de Fail2Ban con jail SSH y lista blanca de IPs)

**Ficheros modificados:**
- Configuración del servicio Fail2Ban (habilitado en el arranque)

---

### Módulo 14: Copias de seguridad

Implementa un sistema de copias de seguridad con estrategia diferencial. Realiza un respaldo completo mensual complementado por respaldos diferenciales semanales que solo almacenan los cambios respecto al último respaldo completo. Restaurar requiere solo dos ficheros: el respaldo completo y el diferencial. Las copias de seguridad se organizan en tres conjuntos independientes: sistema (`/etc`), usuarios (`/home`) y rutas adicionales personalizadas definidas por el administrador.

Cada conjunto se comprime con `tar --listed-incremental` (generando un fichero `.snar` de referencia para los diferenciales), se cifra con GPG AES-256, se verifica con hash SHA-256 y se elimina la versión sin cifrar tras el cifrado. Se mantiene un historial de 4 meses de copias de seguridad.

**Jerarquía de carpetas y nomenclatura:**

```
/var/backups/hardening/
├── backup_sistema_completo_YYYYMMDD_HHMMSS.tar.gz.gpg
├── backup_sistema_completo_YYYYMMDD_HHMMSS.tar.gz.gpg.sha256
├── backup_sistema_diferencial_YYYYMMDD_HHMMSS.tar.gz.gpg
├── backup_sistema_diferencial_YYYYMMDD_HHMMSS.tar.gz.gpg.sha256
├── backup_usuarios_completo_YYYYMMDD_HHMMSS.tar.gz.gpg
├── backup_usuarios_completo_YYYYMMDD_HHMMSS.tar.gz.gpg.sha256
├── backup_usuarios_diferencial_YYYYMMDD_HHMMSS.tar.gz.gpg
├── backup_usuarios_diferencial_YYYYMMDD_HHMMSS.tar.gz.gpg.sha256
├── backup_extra_completo_YYYYMMDD_HHMMSS.tar.gz.gpg
├── backup_extra_completo_YYYYMMDD_HHMMSS.tar.gz.gpg.sha256
├── backup_extra_diferencial_YYYYMMDD_HHMMSS.tar.gz.gpg
├── backup_extra_diferencial_YYYYMMDD_HHMMSS.tar.gz.gpg.sha256
├── sistema.snar                # Referencia de snapshot para diferenciales del sistema
├── sistema_completo.snar       # Copia del snar del último respaldo completo del sistema
├── usuarios.snar
├── usuarios_completo.snar
├── extra.snar
└── extra_completo.snar
```

Todos los ficheros se almacenan de forma plana en `/var/backups/hardening/` (sin subdirectorios). La convención de nomenclatura sigue el patrón: `backup_{sistema|usuarios|extra}_{completo|diferencial}_YYYYMMDD_HHMMSS.tar.gz.gpg`, con su correspondiente fichero de hash `.sha256`. Los ficheros de snapshot `.snar` gestionan las referencias diferenciales contra el último respaldo completo.

**Ficheros creados:**
- `/var/backups/hardening/` (directorio raíz de backups, permisos solo para root)
- `/etc/hardening/backup.key` (contraseña de cifrado GPG, lectura/escritura solo para el propietario)
- `/etc/hardening/backup.conf` (rutas extra personalizadas para backup)
- `/etc/cron.d/` (entradas de cron: respaldo completo el día 1 de cada mes a las 02:00, diferencial todos los domingos a las 02:00)
- Ficheros de backup en formato `.tar.gz.gpg` con hashes `.sha256` y ficheros de referencia `.snar`

**Restauración:** El proceso de restauración es interactivo. Los respaldos del sistema (`/etc`) son obligatorios, mientras que los de usuarios (`/home`) y rutas extra son opcionales y se solicita confirmación. Se aplica primero el respaldo completo y después el último diferencial. Tras restaurar el respaldo del sistema, opcionalmente ofrece reinstalar los paquetes desde una lista guardada.

## Registro de errores

La herramienta registra automáticamente todos los errores en `/var/log/hardening/`, con un fichero de log independiente por módulo. Cada entrada de log incluye la fecha, hora y una descripción del error, proporcionando trazabilidad para la resolución de incidencias.

## Retroalimentación visual

Durante la ejecución, la herramienta proporciona mensajes en tiempo real codificados por colores ANSI:

- **\[CORRECTO\]** (verde): medida aplicada o verificada con éxito
- **\[AVISO\]** (amarillo): requiere atención o presenta una condición no crítica
- **\[ERROR\]** (rojo): la operación ha fallado y requiere intervención manual
- **\[INFO\]** (azul): mensaje informativo sobre el progreso de la ejecución

## Aviso legal

Esta herramienta se proporciona "tal cual", sin garantía de ningún tipo, expresa o implícita. El autor no se hace responsable de ningún daño, pérdida de datos, configuración incorrecta del sistema o interrupción del servicio derivados del uso o mal uso de esta herramienta. Úsala bajo tu propia responsabilidad. Se recomienda encarecidamente probar la herramienta en un entorno de no producción antes de aplicarla en un servidor en activo, y disponer siempre de una copia de seguridad del sistema antes de ejecutar cualquier módulo de fortificación.

## Licencia

Este proyecto fue desarrollado como Trabajo Fin de Grado (TFG) en la UNIR. Consulta el repositorio para más detalles sobre la licencia.
