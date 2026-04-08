# Metodología técnica de hardening integral automatizado para Ubuntu Server 24.04 LTS

## Descripción del Proyecto
Este repositorio contiene el código fuente y los scripts de automatización desarrollados como parte del Trabajo Fin de Estudios (TFE). El proyecto propone el diseño y desarrollo de una metodología técnica de securización (hardening) integral orientada específicamente a servidores Ubuntu Server 24.04 LTS. 

Nace con la motivación de ofrecer soluciones de ciberseguridad accesibles y eficientes para las Pequeñas y Medianas Empresas (PYMEs), las cuales sufren las mismas ciberamenazas (como ransomware o phishing) que las grandes corporaciones, pero a menudo carecen de los recursos financieros, infraestructura y personal especializado para defenderse de manera eficaz. 

Todo el proceso se materializa mediante scripts desarrollados en Python, aprovechando su presencia nativa en Ubuntu Server y sus bibliotecas estándar (os, subprocess, shutil), eliminando por completo la necesidad de instalar dependencias externas.

## ¿Qué se intenta conseguir? (Objetivos)
El objetivo principal de esta aportación es permitir que los administradores de sistemas en pequeñas organizaciones puedan desplegar una arquitectura de servidor robusta de forma sencilla y guiada. 

Con este proyecto se consigue:
*   Reducir la superficie de ataque: Mitigar proactivamente la probabilidad de sufrir brechas de datos o accesos no autorizados en entornos con recursos limitados.
*   Implementar Defensa en Profundidad: Proteger el sistema mediante múltiples capas de controles de seguridad independientes (desde la protección física hasta la seguridad perimetral de red).
*   Garantizar el cumplimiento normativo: Alinear la configuración del servidor con los estándares de ciberseguridad más exigentes, como los CIS Benchmarks, el RGPD, la norma ISO 27001 y el marco nacional CCN-STIC 610-25.
*   Reducir la carga de trabajo técnica: Automatizar tareas complejas a través de una interfaz de usuario guiada que no requiere conocimientos avanzados de administración, previniendo así el estrés y el síndrome del trabajador quemado (burnout) en el personal informático.
*   Validación empírica: Cuantificar la eficacia de las medidas aplicadas mediante herramientas de escaneo y auditoría como OpenSCAP y Lynis, comparando el estado del sistema antes y después del hardening.

## Capas de Seguridad Implementadas (borrador)
Cada módulo de los scripts de automatización ha sido justificado identificando el vector de ataque que mitiga y su correspondencia con la tríada CIA (Confidencialidad, Integridad y Disponibilidad). Las capas abordadas incluyen:

1.  Protección física y del arranque: Configuración segura de GRUB, bloqueo de reinicios forzados y deshabilitación del acceso a almacenamiento USB.
2.  Gestión de usuarios y autenticación: Políticas de contraseñas robustas y configuración estricta de módulos PAM.
3.  Protección del sistema de ficheros: Gestión de permisos y aplicación de atributos inmutables.
4.  Bastionado del Kernel: Ajuste de parámetros sysctl para prevenir ataques de red y spoofing.
5.  Control de Acceso Obligatorio (MAC): Confinamiento de aplicaciones críticas usando AppArmor.
6.  Detección de intrusiones y auditoría: Verificación de integridad de ficheros con AIDE y registro de eventos con auditd.
7.  Seguridad perimetral: Configuración de cortafuegos mediante UFW y nftables.


## Uso y Ejecución
Por ahora, los módulos han de ejecutarse independientemente mediante "sudo python3 modulo.py"