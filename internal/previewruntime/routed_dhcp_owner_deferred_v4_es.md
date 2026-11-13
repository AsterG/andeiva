# Propietario DHCP diferido v4 — contrato interno

Implementación aislada: pendientes revisión independiente, integración agrupada,
pruebas nativas DHCP/privsep/limpieza y mediciones. V3 conserva su perfil inmediato
y contrato. Ninguno es endpoint administrativo público ni versión operativa.

`PrepareRoutedDHCPDeferredOwnerV4` acepta plan DHCP canónico seleccionado por root
y descriptors retenidos. Prepara productor root, montajes privados acotados y
canales; no inicia dhcpcd. WAN estática/NoNetwork no crean productor y se rechazan.
Desired.Hash es fijo por incarnation: cambiar plan exige selección root y nuevo
owner/scope. No resuelve attach dinámico NoNetwork→DHCP en la factory.

`TakeReaderFiles` transfiere una sola vez pipes Current y pidfd real del productor,
sin pidfd de adquisición ficticio. El binding v4 autenticado por root fija
LeaseOwner al PID/start del productor y boot/run/incarnation/Desired. Helper usa
`NewRoutedDHCPDeferredReaderV4`; API no recibe estos recursos. Root retiene otro
pidfd del productor. V3/v4 rechazan sus frames/bindings entre sí. El rol separado
usa FD3..10 existentes; asignar FDs del helper sigue pendiente, sin reutilizar
integridad o recibos de retiro.

Sólo root llama `Activate`, una vez, después de probar revisión seleccionada,
integrityReady del helper, bootstrap/readback LAN y EmptyListeners independiente.
Son precondiciones del supervisor, nunca un booleano API. Current no puede
activar, confirmar, detener ni seleccionar plan.

Root envía activate por canal privado. El rol inicia `dhcpclient.StartIsolated`,
fija pidfd/PID/start/parent/net/mount de dhcpcd real y reporta su identidad. Root
la verifica independientemente, retiene su propio pidfd del hijo y envía confirm
de esa identidad exacta. Sólo entonces Current puede leer evidencia confirmada.
Antes devuelve indisponibilidad sin lease, epoch ni autoridad R2. Fallar termina
la incarnation sin retry/reattach. Activación acotada a diez segundos; Current
mantiene 8 KiB/dos segundos, incluida espera del lock.

Event.PID se contrasta con dhcpcd real, nunca con el productor. Helper comprueba
pidfd del productor; el rol comprueba vida del hijo antes/después de Current y
mediante vigilancia de 100 ms durante inactividad. Muerte del hijo invalida la
incarnation: no admite PID reciclado, start cambiado ni otro hijo. dhcpcd mantiene
renovación/rebind normales. Secuencia RPC difiere de epoch/secuencia del lease;
consultas repetidas conservan fact idéntico y plazo BOOTTIME original.
Caducidad, JSON/replay/perfil inválido, EOF y cancelación nunca usan leases
almacenados. Indisponibilidad observada revoca el epoch anterior.

Stop root antes de activar no inicia hijo. Después detiene/recolecta hijo y
descendientes adoptados antes de confirmar. Control inválido/EOF detiene sin
confirmar éxito. Fallo de inicio/activación o muerte abrupta exige drenaje externo
del cgroup completo antes de retirar scope. Muerte del líder no basta.

Requisitos root/privsep, rutas fijas y límites de montajes: [v3](routed_dhcp_owner_v3_es.md).
No se afirma NET_RAW aislada, nuevo motor, privilegios extra API/helper ni cambio
de unit. Standby consume productor y montajes sólo con plan DHCP seleccionado.
CPU/RAM/latencia y lifecycle nativo pendientes.

Pruebas sin privilegios con Go 1.27.4 y `GOTOOLCHAIN=local`:

```sh
go test -race ./internal/previewruntime -run TestRoutedDHCP -count=1 -timeout=2m
go vet ./internal/previewruntime
go build ./internal/previewruntime
GOOS=windows GOARCH=amd64 go test -c ./internal/previewruntime -o /tmp/andeiva-owner-v4-windows.test.exe
```

Usan pipes reales y dobles de adquisición/vida del proceso, incluyendo regresiones
v3. No ejecutan montajes privilegiados, DHCP ni VM. No prueban Docker/EKS ni
readiness nativa. Rollback: retirar v4 sin integrar y restaurar helpers v3 desde
commit padre; sin cambios en configuración instalada o estado compartido.
