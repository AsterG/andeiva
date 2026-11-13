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

**La recuperación tras caída sigue bloqueada.** Los anchors heredados se validan
pero se rechazan antes de crear otro scope. `ENODEV`, un path ausente, otro
cgroup o el manifest por sí solos no autorizan limpieza. La observación nativa
del antiguo `cgroup.events` aún no es autoridad de retirada. No se promete
persistencia de FD tras reinicio de OS, suspensión o pérdida de energía.

Las pruebas focales usan dobles explícitos del manager y transferencia Unix real
para barriers. No acreditan almacenamiento systemd nativo ni teardown
privilegiado. Siguen pendientes calificación nativa de almacenamiento, parada,
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

## Calificación nativa del almacén (opt-in, aún no ejecutada)

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

La captura inicial también verifica que el manager identifica este proceso Root como MainPID, el cgroup fijo y Delegate=no. El manifest registra InvocationID; rechaza controles del cgroup delegados o escribibles por grupo/otros. El parser del antiguo events distingue estado populated vivo de ENODEV en el FD original exacto, pero ninguna observación habilita teardown. La retirada tras caída aún requiere lector G1/R2 completo autenticado y el bloqueo de publicación existente; el manifest no fabrica prueba del estado seleccionado.
