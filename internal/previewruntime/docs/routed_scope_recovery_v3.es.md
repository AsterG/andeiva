# Retención del scope Root y retirada normal

El servicio agrupado experimental publica un manifest operacional root y siete
descriptores antes de crear o habilitar enlaces L2. La instalación debe llamar a
`PrepareRoutedScopeRecoverySlotV3` para reservar `grouped-scope-v3`: archivo fijo
root 0600 de 4096 bytes. El runtime no lo crea, amplía ni sobrescribe si quedó
pendiente. Es evidencia operacional, no otra base de configuración; G1/R2
seleccionado sigue siendo obligatorio.

Los FD retienen manifest, namespace de red gateway, namespace de montaje,
archivo original previo al bind, directorio privado, cgroup original y su
`cgroup.events`. Este último se captura con `openat` del cgroup antes de efectos;
sus identidades quedan registradas. Root persiste y sincroniza el manifest,
envía cada FD con `FDPOLL=0`, espera un barrier separado y consulta el almacén
real del manager. Deben coincidir los siete nombres, dispositivo/inode, modos y
acceso. El barrier solo no acredita aceptación. Una publicación parcial conserva
la evidencia y bloquea efectos; no reintenta ni descarta entradas desconocidas.

La unidad usa `NotifyAccess=main`, `FileDescriptorStoreMax=7` y
`FileDescriptorStorePreserve=yes`. Root MAIN consume `LISTEN_FDNAMES` antes de
abrir otros FD: listener de administración solo, o listener y los siete anchors,
en cualquier orden. Rechaza duplicados, conjuntos parciales, nombres ajenos y
alias. Duplica con CLOEXEC; el supervisor mantiene la validación de namespace,
interfaz y dirección del listener.

La parada normal exige hijos drenados y teardown explícito exitoso de enlaces y
namespace; después elimina las copias exactas del manager, espera el barrier y
verifica ausencia. Cierra sus copias retenidas antes de escribir el recibo de
retirada existente. Solo un recibo completado exacto y un almacén vacío permiten
limpiar el manifest. Ausencia de rutas y cierre de FD no equivalen a destrucción
RCU sincrónica. Un fallo conserva evidencia y evita un recibo falso.

El consumidor experimental del mismo boot liga los anchors heredados al trabajo
CURRENT seleccionado mediante el lector privado sin capacidades. Root mantiene
el `checkpoint.lock` existente durante todo el proceso. G1/R2 completo selecciona
DHCP, Boot, Pending o Active; rechaza coincidencias históricas, corrupción,
intents ordinarios no soportados y scopes aún no seleccionados. No fabrica un
scope inicial antes de L2.

La ruta de cgroup vivo exige invocación no delegada, sin hijos y cero miembros
en grupo antiguo distinto, o únicamente Root si se reutilizó el mismo grupo.
La nueva ruta de desactivación exige ENODEV sin bytes en el FD original
autenticado, inodos antiguo/actual distintos del mismo dispositivo e invocaciones
reales distintas. Revalida selección exacta bajo el lock original, siete anchors,
BootID/host actuales, unidad no delegada y drenaje con sólo Root. ENOENT, lectura
parcial, cambio de identidad o cualquier prueba fallida rechazan. Revisión
independiente y calificación nativa pendientes; el intento previo se bloqueó
en el rechazo ENODEV anterior conservando siete FD. No añade recuperación tras
reboot del OS, suspensión o pérdida de energía.

Tras prueba seleccionada y drenaje, comandos fijos cierran forwarding IPv4/IPv6,
lo verifican y retiran sólo hijos MACVLAN privados reconocidos del namespace
retenido distinto del host. Revalidan el selector antes de detach y antes de
soltar el almacén. Un hilo dedicado entra al mount namespace privado retenido,
comprueba pin gateway y underlay exactos, desmonta y retira el archivo; su
contexto de filesystem no vuelve al pool de Go. La limpieza acepta únicamente
metadata exacta, netns anclado, api vacío y los dos sockets IPC tipados. Root usa
CAP_CHOWN existente sólo en el directorio IPC probado después del drenaje.
Entradas desconocidas o cambiadas bloquean; sin borrado recursivo ni capacidades
adicionales. Drop verificado, cierre de pins y comprobación del lock preceden el
recibo, que no afirma rollback de direcciones ni renovación del lease.

Un detach/chown/unlink parcial puede exigir inspección del operador; no se toma
propiedad incierta ni ausencia de anchors como éxito idempotente. La retirada
tras caída en el mismo boot aún no tiene calificación nativa.

Las pruebas focales usan dobles explícitos del manager y transferencia Unix real
para barriers. No acreditan almacenamiento systemd nativo ni teardown
privilegiado. Siguen pendientes calificación nativa de parada,
fallos parciales, SIGKILL y recursos. No se activó el host ni la appliance.

```sh
go test -race ./internal/previewruntime -run TestRoutedScopeRecoveryV3 -count=3
go vet ./internal/previewruntime
go build ./internal/previewruntime
bash packaging/preview/tests/api-lifetime-unit-graph.sh
```

[systemd257 service FD store](https://www.freedesktop.org/software/systemd/man/257/systemd.service.html),
[named inheritance](https://www.freedesktop.org/software/systemd/man/257/sd_listen_fds.html),
[notification barriers and FDPOLL](https://www.freedesktop.org/software/systemd/man/257/sd_notify.html),
[manager readback](https://github.com/systemd/systemd/blob/v257/src/analyze/analyze-fdstore.c).

## Calificación nativa del almacén (opt-in)

`TestRoutedScopeRecoveryV3NativeStore` debe ejecutarse directamente como MainPID
de `andeiva-preview-grouped.service` transitoria en un cliente Debian 13 aislado
donde servicio y socket estén ausentes. Root debe comprobar `LoadState=not-found`
en ambos antes de lanzar; nunca sustituir una unidad instalada. La prueba valida
root/sin CI, MainPID, propiedades transitorias, cgroup exacto y namespace de
montaje distinto de PID1 antes de efectos. Crea solo gateway vacío, pequeño
directorio privado y manifest preasignado: sin L2, listeners, grant ni recibo.
Los siete anchors reales pasan por Store/barrier/readback, VerifyStored separado,
Drop/barrier/readback vacío y Close local.

Timeout de prueba 30s; unidad 45s y consultas acotadas. Root conserva la ruta
única y el InvocationID. Fallos parciales de Store/Drop retienen evidencia y
anchors: inspeccionarlos antes de limpiar. SKIP o rechazo no root no acreditan
éxito nativo. Root debe verificar después almacén vacío, limpieza, invariantes
de red/montaje del host y recursos CPU/memoria. No acredita recuperación huérfana.

```sh
# Root preflight must show not-found for both units.
systemctl show -p LoadState andeiva-preview-grouped.service
systemctl show -p LoadState andeiva-preview-grouped.socket
# Substitute the independently verified, root-owned test artifact path.
systemd-run --unit=andeiva-preview-grouped.service --wait --pipe \
  --property=Type=exec --property=NotifyAccess=main \
  --property=FileDescriptorStoreMax=7 --property=FileDescriptorStorePreserve=yes \
  --property=PrivateMounts=yes --property=PrivateTmp=yes \
  --property=KillMode=control-group --property=NoNewPrivileges=yes \
  --property=RuntimeMaxSec=45s --property=TimeoutStopSec=3s \
  --property=TasksMax=64 --property=LimitNOFILE=256 --property=MemoryMax=256M \
  --setenv=ANDEIVA_SCOPE_STORE_NATIVE=1 \
  /ROOT_OWNED_FIXTURE/routed-scope-store-native.test \
  -test.run=^TestRoutedScopeRecoveryV3NativeStore$ -test.v -test.timeout=30s
```

La captura inicial también verifica que el manager identifica este proceso Root como MainPID, el cgroup fijo y Delegate=no. El manifest registra InvocationID; rechaza controles del cgroup delegados o escribibles por grupo/otros.

La fixture anterior Store/Drop de siete anchors pasó en Debian 13 en 0.11s, con
invariantes externos del host sin cambios. CPU/RAM no estuvieron disponibles.
No acredita el nuevo consumidor de retirada ni sus fallos parciales.
