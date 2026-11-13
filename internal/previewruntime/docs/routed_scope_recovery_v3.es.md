# Requisitos para recuperar el scope Root

Este incremento experimental todavía no recupera un supervisor muerto. Añade
captura de anchors reales, registro operacional Root de 4096 bytes exactos,
constructor readonly y lectura real del FD store del manager. No desmonta,
borra paths, cierra el gate DHCP ni emite recibos. G1/R2 seleccionado sigue
siendo una autoridad independiente y obligatoria.

`PrepareRoutedScopeRecoveryRecordV3` exige root real, BootID/host actuales,
mount namespace actual y cgroup dedicado exacto sin otros procesos. Recibe seis
FD readonly: registro preasignado, gateway, mount namespace, underlay original
anterior al bind, directorio netns root0700 y directorio cgroup2. El registro liga
dev/inode, digest de metadata e identidades. Root debe persistir/fsync antes de
crear o habilitar L2. El checksum detecta escritura parcial; no autentica.

`OpenRoutedScopeRecoveryV3` verifica dueño/modo/asignación del archivo, encoding,
acceso/tipo/identidad de los FD, ámbito distinto del host y BootID actual. Duplica
con CLOEXEC. `VerifyStored` ejecuta una consulta busctl fija y acotada; exige los
seis nombres exactos con modo/dev/inode/flags coincidentes. No confía en paths ni
orden y revalida registro/anchors tras la lectura. Esto prueba retención, nunca
drenaje ni permiso para emitir recibo.

Falta integrar FDSTORE con aceptación observada antes de L2; recibir FDs nombrados
en el siguiente MAIN separando el socket de administración; probar drenaje del
cgroup anterior retenido; retirar el scope exacto dentro del mount namespace
retenido; liberar copias del manager y verificar ausencia; recién entonces emitir
el recibo existente. Pin ausente, unidad renombrada, cgroup nuevo vacío o manifest
solo no prueban retiro. Cgroup antiguo offline/eliminado sigue bloqueado hasta
implementar su prueba de drenaje. La parada normal también debe liberar copias
del manager antes del recibo. Fallos parciales conservan evidencia y bloquean.

Propuesta no aplicada: `NotifyAccess=main`, `FileDescriptorStoreMax=6`,
`FileDescriptorStorePreserve=yes`. Recuperar en siguiente MAIN; no asumir que
ExecStopPost recibe FDs guardados. Nombres fijos sin política, credenciales ni
hash de trabajo. Sin cambios de dependencias, unit, host o appliance. Pendientes
SIGKILL/stop/start nativos, herencia FD, teardown, fallos parciales y recursos.
No se afirma recuperación por reboot, suspensión o power-loss mediante estos FD.

Tests: encoding, scope/fase alterados, aliases, escritura parcial, FD writable o
tipo incorrecto, rechazo capless y readback incompleto/duplicado/modificado.
Respuestas del manager en tests son dobles explícitos, no evidencia nativa.

```sh
go test -race ./internal/previewruntime -run TestRoutedScopeRecoveryV3 -count=1
go vet ./internal/previewruntime
go build ./internal/previewruntime
```

Fuentes: [ciclo FD store systemd257](https://www.freedesktop.org/software/systemd/man/257/systemd.service.html),
[herencia nombrada](https://www.freedesktop.org/software/systemd/man/257/sd_listen_fds.html),
[barrier de procesamiento, no aceptación](https://www.freedesktop.org/software/systemd/man/257/sd_notify.html)
y [protocolo DumpUnitFileDescriptorStore](https://github.com/systemd/systemd/blob/v257/src/analyze/analyze-fdstore.c).
