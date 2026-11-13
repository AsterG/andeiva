# Trabajo DHCP seleccionado (experimental)

La extensión opcional `configuration.routed-dhcp-selected.v3` usa el selector de
configuración y los tres pools de reserva existentes. Los registros estáticos
omiten los nuevos campos; los lectores anteriores rechazan la feature obligatoria.

El trabajo liga boot/run/namespace, revisión de red y baseline LAN exactos,
PID/inicio/incarnación del propietario, época DHCP, secuencia del controlador,
deadline BOOTTIME absoluto original y dirección/ruta WAN propias. El hash sólo
correlaciona. El lector G1/R2 independiente del helper debe emitir autoridad antes
de los efectos; el writer verifica el readback del helper autenticado.

Esta primera versión cierra gate y forwarding, retira la WAN hasta el baseline
observado, archiva su R2 terminal mediante ambos selectores y prepara la nueva
concesión. Interrumpe la renovación: no ofrece la optimización de renovación sin
cambios L3 del executor existente. Las fases prepared/applied/withdrawn se auditan.
La evidencia terminal persistida impide reutilizar la misma época/secuencia.
Confirm y rollback nunca restauran un token anterior.

El reinicio exige una capacidad de recuperación confiable: cerrar gate, resolver
el trabajo por lectura independiente y retirar sólo el delta WAN propio exacto.
Sin prueba, con drift o con otro boot/run se bloquea la apertura. `withdrawn`
significa LAN original y WAN vacía observadas, no restauración de una concesión.

Evidencia actual: pruebas unitarias con archivos y pools reales, y autoridad de
kernel simulada explícitamente; cubren archivo/reutilización, replay, pérdida de
autoridad, fase incorrecta y boot diferente. Siguen pendientes runtime DHCP
seleccionado nativo, bootstrap LAN y transporte autenticado. La expiración kernel
supone ejecución continua; no soporta suspensión, pausa VM ni restaurar snapshots.
No habilita adopción de la red del host.

El perfil separado de bootstrap LAN Version 3 reutiliza Boot/R2 seleccionado.
La preparación de sólo lectura exige ambas interfaces IPv4 vacías. Después de
leer la política de denegación sólo aplica la dirección LAN estática; WAN queda
vacía hasta seleccionar la concesión. El inventario local declara sólo LAN.
Retirar WAN no otorga propiedad LAN: restaurarla exige el snapshot Boot original
seleccionado. Las pruebas cubren orden, compensación parcial y expiración Boot
sin confirmar con dobles explícitos de kernel. Calificación nativa pendiente.
