# TP-DHCP-LAN-001 — Empaquetado offline del servidor DHCPv4

Responsable: backend/control plane. Fecha: 2026-11-13. Estado: **propuesta; no
seleccionado, implementado, instalado ni calificado**. Base main `ca4afb2`;
contrato PR70 `dee8c1b` y pruebas límite `06d6c67`. No cambia API ni runtime.
[English](en.md) · [Português](pt.md) · [Evidencia de dependencias](evidence.md).

## Decisión propuesta para ADR

Evaluar `kea-dhcp4-server` de Debian13, `kea-common` de versión exacta y clausura
completa verificada. Primer laboratorio con memfile persistente: sin servidor de
base de datos, hooks comerciales, DDNS, DHCPv6, relay, HA ni control-agent.
Memfile no queda autorizado para distribución sin pruebas de durabilidad.

| Opción | Consecuencia |
|---|---|
| Mantener sólo validador PR70 | Estado actual; riesgo runtime mínimo, sin servidor funcional. |
| Componente Kea DHCPv4 | Candidato existente recomendado para evaluación; exige aislamiento raw, durabilidad, licencia y mediciones. |
| dnsmasq | Comparador de consumo existente; requiere pruebas independientes de paridad, aislamiento y persistencia. No se presume menor consumo. |

Aplican el proceso de cambio tecnológico y ADR-033 sin HA v1. Los ADR WAN
050/058 no autorizan un servidor. Revisión de arquitectura, seguridad, licencia y
rendimiento antes de ADR numerado aprobado e implementación. Mantener PR70:
32 scopes, 65.536 direcciones declaradas, exclusiones, reservas, binding LAN
seleccionado y `T1 < T2 < lease`. Rechazar habilitación incompatible explícitamente;
no reducir silenciosamente el contrato.

## Entrada offline e instalación

La [evidencia](evidence.md) verifica 51 paquetes por arquitectura, 94 archivos
distintos amd64/arm64 contra metadata Debian firmada. No es un sistema mínimo
instalable ni actualización ANDEIVA firmada. Paquetes Essential, systemd,
AppArmor y estado dpkg real del destino son prerrequisitos independientes.
Memfile no elimina dependencias cliente MariaDB/PostgreSQL; sus servidores quedan
fuera. No usar metapaquete `kea`, Recommends, apt online ni sustituciones de versión
en la appliance.

Reutilizar el modelo de confianza del builder/verificador offline existente, no
su instalador específico de boot. Resolver en build contra snapshot firmado y
baseline autenticado; conservar Depends/Pre-Depends y alternativas, versiones
binarias/fuente, arquitectura, tamaños/hash, metadata, fuentes, licencias y SBOM.
Manifiesto liga delta exacto y hash del estado destino. Si cambia baseline,
resolver nuevamente. No bajar dependencias nuevas ni actualizar libc/SSL como
efecto lateral; actualización OS es otra transacción revisada.

Antes de efectos: firmas ANDEIVA confiables, procedencia Debian, reloj,
arquitectura, espacio/inodos, backup y delta exacto. Simulación sólo local con
`--no-download --no-install-recommends --no-remove`; comparar todas las acciones
con manifiesto. No `trusted=yes`, `--allow-unauthenticated` ni desactivar caducidad.
Simulación no demuestra disponibilidad de archivos: verificar hashes y comprobación
download-only/no-download de caché antes de dpkg.

## Impedir autoarranque

Scripts Debian revisados intentan enable/start/restart, cambian cuentas/permisos
y recargan AppArmor: **policy-rc.d sola no basta**.

1. Serializar paquetes/transiciones; journal durable del delta, unidades, política,
   configuración y datos preservados. Rechazar servidor/cuenta/unidad/datos ajenos;
   no adoptar ni detener servicios existentes sin autoridad específica.
2. Antes de unpack/configure, máscara persistente propia y verificada de
   `kea-dhcp4-server.service`. Conservar tras reboot; futuro servicio seleccionado
   pertenece al launcher ANDEIVA. Probar que unmask/enable del paquete no la vence.
3. Scripts aprobados en mount namespace privado, vista inmutable de policy-rc.d
   que niega activación Kea y delega otros pedidos a política original intacta.
   Si no puede preservar comportamiento, rechazar. Si falta archivo, vista privada
   del directorio, no reemplazo temporal en host. Comprobar identidad/hash original
   y mount view del padre; no trucos de PATH/entorno.
4. Revisar todos los scripts/triggers del delta: cuentas, ldconfig, AppArmor y
   daemon-reload son efectos reales. Ejecución directa/desconocida de daemon bloquea
   paquete. No desactivar AppArmor ni aceptar error del parser como éxito.
5. Verificar máscara/enablement y ausencia de proceso, LFC, socket raw/packet/UDP
   y respuesta DHCP antes de cerrar instalación. Interrupción conserva journal y
   máscara; `apt -f install` genérico no es recuperación.

## Runtime, datos y recursos

API/CLI/web usan candidato validado, RBAC, auditoría y coordinador existente.
Running tras activación verificada y confirmación; Startup sólo con Save. No
aceptar JSON de motor, ejecutables, rutas, namespaces o privilegios del cliente.
Leases son estado operativo, no segunda base de configuración. Ocultar identidades
de motor/versiones y diagnóstico privilegiado del administrador funcional.

Identidad de servicio distinta de API/helper; namespace propio fijado e interfaces
LAN seleccionadas, nunca `*`, host o WAN. Revisar NET_RAW/NET_BIND_SERVICE sin
otorgarlas a API/helper. Kea usa sockets raw para clientes directos y el
[manual versionado](https://kea.readthedocs.io/en/kea-2.6.3/arm/dhcp4-srv.html#interface-configuration)
advierte bypass de filtrado IP: INPUT no prueba bloqueo DHCP. Exigir frontera
kernel y retirada verificadas antes de respuestas, reemplazo de interfaz, muerte
y drenaje. Allowlist de interfaces tampoco confina un proceso NET_RAW comprometido
que abre otra interfaz del mismo namespace. No ubicarlo junto a WAN sin frontera
revisada; nueva topología sólo LAN exige aprobación aparte. No relajar readiness.

Disabled exige cero proceso servidor/LFC, socket raw/UDP/control, timer, worker
exclusivo o regla/config generada activa. Retener datos dormidos. Drenar cgroup
completo y verificar descriptores/política; una solicitud stop o `ss` UDP vacío
no basta. No borrar auditoría central ni cambiar forwarding/NAT al desactivar.

Cuota/reserva dedicada incluye leases, todos los
[intermedios LFC](https://kea.readthedocs.io/en/kea-2.6.3/arm/lfc.html), crecimiento
durante limpieza, configuración temporal y recuperación de upgrade. Objetivo
preliminar **512 MiB activos + 512 MiB de reserva**: no capacidad demostrada.
Medir tamaño máximo de fila/churn/copias y rechazar habilitación si no cabe;
65.536 leases requieren prueba propia. No truncar/rotar leases como logs. Logs
diagnósticos separados y acotados; auditoría protegida sigue Storage Manager.
Umbral preventivo debe detener asignación/renovación antes de perder durabilidad;
si no se prueba esta frontera, bloquear selección. ENOSPC/inodos/corrupción no
pueden producir base vacía ni olvido de concesiones.

Memfile no prueba por sí mismo orden ACK→persistencia durable. Medir fsync,
corte de energía y retroceso de reloj; incompatibilidad exige propuesta de backend,
no falsa garantía. CPU/RSS/PSS, pico LFC, arranque, escrituras y desactivación a cero
pendientes en 2 GiB y ambas arquitecturas. Sin afirmación de rendimiento.

## Upgrade, retiro y rollback

Quiesce mediante operación seleccionada durable antes de modificar paquetes.
Detener servidor/LFC, verificar drenaje, sync y snapshot completo del estado de
leases, versiones de compilador/motor y referencias de auditoría. Nunca purgar
leases/audit en scripts, remove, autoremove o rollback. Datos ANDEIVA separados
de defaults del paquete, permisos/AppArmor revisados. Retirar sólo delta propio
sin dependientes ajenos; conservar dependencias dormidas si son compartidas.
Reinstalación debe recuperar datos retenidos.

Rollback conserva concesiones emitidas desde la configuración anterior: restaurar
snapshot viejo puede duplicar direcciones. Probar lectura de datos actuales por
motor anterior antes de downgrade; si incompatible, permanecer desactivado con
estado recuperable. Reducir/mover scope conserva ownership hasta expiración
original o release verificado, sin segundo almacén autoritativo. Crash continúa
misma operación/deadline. Cambios de contrato coordinador/lease requieren ADR propio.

## Pruebas nativas futuras — ninguna ejecutada

Los IDs y matriz completos están en [EN](en.md#acceptance-gates--future-native-tests-not-executed).

| ID | Caso | Resultado obligatorio |
|---|---|---|
| PKG-01 | Debian13 mínimo amd64/arm64 sin motor, egress desconectado | Delta local exacto; cero proceso/socket/respuesta antes de enable; capturas de dpkg/unidad/política/AppArmor/red host. |
| PKG-02 | Dependencia ausente/corrupta/arquitectura errónea, firma/caducidad/baseline inválido | Rechazo antes de unpack, cero cambios. |
| PKG-03 | Política propia/ausente, umask restrictivo, motor/unidad/datos ajenos | Preservar bytes/comportamiento; rechazar adopción. |
| PKG-04 | Kill tras máscara/unpack/configure/enable/journal, reboot | Sin arranque stock; reanudar delta exacto o bloquear preservando journal. |
| RUN-01 | Clientes reales en dos scopes, captura WAN | DORA/renew/expiry/opciones; ninguna IP excluida/router o colisión; reserva fuera pool válida; cero respuesta host/WAN. |
| RUN-02 | Disable con leases/LFC, reboot/re-enable | Cero runtime exclusivo, ownership retenido sin duplicados. |
| RUN-03 | Tráfico raw durante retirada/cambio de link/muerte | Fence independiente detiene respuestas; no aceptar firewall IP como única prueba. |
| DATA-01 | Cuota/inodos/readonly/short write/fila corrupta/kill en cada rename LFC | Sin ACK sin ownership recuperable ni fallback vacío; audit/reservas preservados. |
| DATA-02 | Corte tras ACK, reloj atrás/adelante | Sin reasignación prematura; evidencia durable y temporal. |
| UP-01 | Upgrade enabled/disabled/interrumpido, datos incompatibles con versión anterior | Preservar estados; rollback incompatible bloqueado y leases/audit intactos. |
| RM-01 | Remove/reinstall/dependiente ajeno/purge | Sin borrado ni remoción ajena; rechazar purge. |
| RES-01 | 1/32 scopes, 1/65.536 leases, churn/flood/LFC/soak24h | Medir PSS/RSS/CPU/disco/inodos/latencia y cero delta disabled; revisión previa a selección. |

Sólo laboratorio autorizado con snapshot e invariantes host independientes.
Metadatos WSL/contenedor no califican runtime de appliance. Sin cambio EKS/Helm.
El [copyright Debian](https://metadata.ftp-master.debian.org/changelogs/main/i/isc-kea/isc-kea_2.6.3-1%2Bdeb13u1_copyright)
incluye MPL-2.0 y avisos adicionales. Revisión completa de licencias/fuentes/SBOM
pendiente; disponibilidad upstream no es aprobación legal. Sin hooks premium.

## Gates de revisión independiente

- Probar unmask, enable, triggers, configuración interrumpida y reinicio contra la máscara persistente; ningún daemon stock debe arrancar.
- Comparar las políticas AppArmor cargadas en el host antes/después, también en fallos. Un namespace de montaje privado no vuelve locales sus efectos.
- Probar un worker comprometido intentando captura/transmisión AF_PACKET fuera del enlace y tráfico DHCP autorizados; exigir denegación efectiva.
- Vincular cada binario distribuido con su fuente exacta, licencia y obligaciones. La licencia del motor no cubre todos los artefactos transitivos.

Son pruebas futuras obligatorias, no evidencia de instalación completada.
### Todos los sockets declarados deben estar disponibles

La evaluación aislada deberá configurar `service-sockets-require-all: true`.
Ocupar un segundo listener LAN declarado antes del arranque y comprobar que el
servidor rechaza la activación parcial, no deja un primer scope utilizable y
notifica el fallo. Liberar el conflicto y verificar la recuperación explícita.
Un proceso activo no demuestra que todas las interfaces declaradas estén servidas.
Es un criterio de aceptación; ANDEIVA todavía no implementa este ajuste del motor.
