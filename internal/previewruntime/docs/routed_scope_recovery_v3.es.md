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
