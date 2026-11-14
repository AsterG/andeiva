# Laboratorio nativo DHCP jobs v4

Fixture preparada; compilación y prueba omitida por opt-in no califican ejecución
nativa. Exclusivamente Debian 13 aislado: no WSL, CI ni appliance instalada.
Los comandos de compilación, artefactos y ejecución están en
[la receta EN](dhcp-jobs-native-v4.en.md). Usar Go 1.27.4 y registrar SHA-256 de
binario, script y hook; directorio root 0755, sin enlaces ni escritura ajena.

Dependencias: dhcpcd, BusyBox con udhcpd, iproute2, nftables, nsenter, setpriv y
mount. udhcpd es solamente un servidor de paquetes de prueba. El orquestador debe
reservar la unidad ausente `andeiva-preview-grouped.service`, exigida por el
productor real, con cgroup root sin delegación y namespace de mounts privado.
No sustituir ni activar una unidad instalada. Preparar `/run/netns` y
`/usr/libexec`; el script instala el hook únicamente sobre tmpfs privado.

El script crea tres namespaces y dos veth aislados, hereda pins FD3–5 y no recibe
PID por entorno. La semilla offline y metadata Schema1 son reales de laboratorio.
El helper productivo comparte el mismo ejecutor LAN entre autoridad y DHCP;
mantiene NET_ADMIN, API sin capacidades y FD15 privado sólo en helper.

Primer modo: Service autenticado NoNetwork→Stage/Validate/Commit/Confirm DHCP,
inspección completa, adquisición real, prueba selected `dhcp_live`, readback de
dirección/ruta desde kernel, renovación natural con nuevo epoch y deadline
original, reinicio únicamente API conservando helper/productor. Rollback con
trabajo DHCP activo debe rechazarse sin cambiar Running ni lease. Marcadores JSON
`ANDEIVA_NATIVE_DHCP_JOBS`: bound, renewed, restarted, rollback-fenced. Limpieza:
`ANDEIVA_NATIVE_DHCP_JOBS_CLEANUP_OK`.

No demuestra retirada transaccional/rollback a NoNetwork, módulo desactivado sin
recursos, expiración, muerte del propietario, tráfico, reboot ni presupuesto de
recursos. El gate residual cerrado sólo desaparece al retirar el namespace
completo. Preservar evidencia de fallos; no eliminar pins con identidad cambiada
o procesos vivos. Ausencia de resultado nunca significa éxito.
