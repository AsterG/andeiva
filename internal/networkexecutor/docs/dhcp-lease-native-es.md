# Fixture DHCP real a LeaseExecutor aislado

Calificación experimental Debian 13. Resultado nativo y recursos de esta unión
pendientes; las pruebas anteriores acreditaron componentes separados. No añade
API, formato persistente, otra base de datos, adopción host ni topología productiva.

Compilar sin privilegios:

```sh
go test -race ./internal/networkexecutor -run DHCPLease -count=1
go vet ./internal/networkexecutor
go test -c -o dhcp-lease-native.test ./internal/networkexecutor
go build -o andeiva-dhcp-hook ./cmd/andeiva-dhcp-hook
bash -n scripts/dhcp-lease-native-isolated.sh
sha256sum dhcp-lease-native.test andeiva-dhcp-hook scripts/dhcp-lease-native-isolated.sh
```

Los dos tests nativos se omiten fuera del harness autorizado: PASS local no es
calificación nativa. Transferir artefactos a directorio nuevo propiedad root,
verificar hashes y archivos regulares de un enlace, root, modo `0555`. Desde ese
directorio, ejecutar cada modo en una unidad systemd separada:

```sh
ANDEIVA_DHCP_LEASE_LAB_AUTHORIZED=1 ./dhcp-lease-native-isolated.sh lifecycle
ANDEIVA_DHCP_LEASE_LAB_AUTHORIZED=1 ./dhcp-lease-native-isolated.sh owner-death
ANDEIVA_DHCP_LEASE_LAB_AUTHORIZED=1 ./dhcp-lease-native-isolated.sh manager-death
ANDEIVA_DHCP_LEASE_LAB_AUTHORIZED=1 ./dhcp-lease-native-isolated.sh broker-death
```

Exige `KillMode=control-group`, `RuntimeMaxSec=360s`, `TimeoutStopSec=10s` y
`LimitNOFILE=256`. La unidad externa empieza en namespaces normales del host;
el harness coteja pins originales con `/proc/1` antes de montar en privado.
Sólo laboratorio Debian descartable autorizado, con `dhcpcd`, BusyBox `udhcpd`,
`ip`, `nft`, `unshare`, `mount`, `setpriv` y Bash. Prohibida ejecución privilegiada
en WSL/CI/clientes. No instala paquetes ni inicia daemons host.

Tres namespaces contienen gestor, servidor DHCP y peer LAN. LAN inicial
`198.18.0.1/24`; WAN vacía. Cliente real root/privsep separado, sólo adquisición;
helper UID/GID62006 sólo NET_ADMIN y no_new_privs=1 con LeaseExecutor real.
Start/Wait permanecen en hilo fijado para parent-death. Pipes anónimos root0600,
extremos heredados exclusivos, dirección validada y close-on-exec autentican el
ensamblado. Bootstrap verifica PID/inicio del padre root, PID hijo,
namespace/boot/run e incarnation DHCP. Frames canónicos acotados privados: no
son entrada JSON pública ni contrato IPC productivo.

El cambio de UID borra Pdeathsig previo al exec. Cada rol rearma SIGKILL después
de autenticar al padre, lee PR_GET_PDEATHSIG y vuelve a comprobar PID/inicio y
cuatro UID root del mismo padre. Retiene ese hilo durante su vida y sólo anuncia
readiness con la señal verificada.

`Current` consulta al propietario real durante cada operación. Conserva el
deadline CLOCK_BOOTTIME exacto del cliente, sin prolongarlo al leer. Grants usan
Epoch/evento real; la secuencia también avanza al revocar. Rebind retira autoridad
y L3 antes de señalar el motor. Un Epoch revocado no vuelve a autorizar. Ningún
comando WAN L3 manual reemplaza al ejecutor.

Forwarding IPv4/IPv6 siempre cero y cadena inet forward drop. Sólo admite DHCP
local WAN UDP68→67 al servidor fijo/broadcast y UDP67→68 desde ese servidor;
el resto de input/output inet cae. Adquisición raw pertenece al rol root/privsep.
No acredita forwarding de tráfico.

`lifecycle`: BOUND, ACK RENEW sin nuevas escrituras L3, rebind, reinicio tras
retiro, muerte servidor/expiración y rechazo de caché offline. `owner-death`:
muerte del cliente root y retiro por pérdida de canal. `manager-death`: muerte
del helper con WAN activa, LAN intacta y reapertura rechazada por WAN ocupada;
WAN permanece hasta destruir namespace. **No es restauración ni recuperación
entre procesos**. Trabajo seleccionado autenticado durable y guard de expiración
independiente en kernel siguen pendientes antes de permitir forwarding.

`broker-death` incorpora un padre relay root real. Tras aplicar el lease real,
sólo mata ese broker: el supervisor subreaper exige pidfd del helper legible y
estado SIGKILL al recolectarlo. Salir normalmente por EOF no sirve como evidencia.
Reabrir WAN ocupada sigue prohibido; no afirma restauración. Muerte del servidor
también exige pidfd legible, no sólo envío de señal. Expiración conserva cada
grant válido posterior, incluido ACK en vuelo; falla si pierde autoridad antes
del último deadline observado. La negativa A→B rechaza indisponibilidad entre
ambos deadlines.

Registrar PASS ejecutado sin skips, hashes, CPU/memoria del cgroup, invariantes
host dual-stack/links/direcciones/rutas/reglas/nftables/forwarding/mounts y ausencia
de descendientes/namespaces tras detener. Salida de PID1 privado y cgroup externo
limpian procesos; no se señala un PID servidor cacheado. Borrar el nombre del
namespace no prueba que desaparecieron todos sus pins.
