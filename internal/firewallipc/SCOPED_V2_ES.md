# IPC v2 preparado para recuperación acotada

[English](SCOPED_V2.md) · [Português](SCOPED_V2_PT.md)

Este transporte no está seleccionado en el runtime desplegado. Los constructores,
mensajes y comportamiento v1 permanecen intactos. No cambia API pública, usuarios,
unidades, reglas del host ni namespaces.

El handshake v2 explícito vincula ejecución del runtime, instancia del helper,
época, dominio fijo y namespace. Exige exactamente `attach_observed.v1` y
`recover_scoped.v1`, en ese orden. Cada mensaje repite esos vínculos y su secuencia.
No existe degradación automática ni verbo v2 `recovered`. Los payloads tipados
rechazan campos duplicados, con mayúsculas alternativas o desconocidos, JSON
adicional, revisiones inválidas y deadlines no canónicos. Se mantienen 64 KiB
por mensaje y 256 KiB para respuestas de observación Local-In.

`attach_observed` compara estado y hash efectivo bajo el mutex del guardian. No
aplica ni restaura reglas, borra leases, extiende plazos o termina recuperación
durable. Si una fase activa ya venció y su temporizador aún no la reconcilió,
rechaza la observación sin ejecutar compensación. Antes del enlace sólo permite
estado, observación y enlace. El bootstrap vacío exacto permite únicamente el
bootstrap canónico de una sola ejecución; después exige idle verificado y hash
no vacío. No representa una política vacía del kernel verificada.

`recover_scoped` ejecuta el CAS existente del guardian sobre ID, hashes y deadline
original antes de compensar. No consume una lease sustituta, tampoco con los
mismos ID/hashes y otro plazo. V2 no llama a recuperación legacy sin alcance.
Una lease existente puede reenlazarse con menos de 500 ms sin rearmarla; una
nueva conserva los límites de 500 ms y 120 s.

La sesión admite un controlador antes de crear trabajo de conexión y conserva
el guardian al desconectarse. Las épocas aumentan sin reutilización. Un fallo
fatal del listener cierra la conexión activa antes de esperar workers. El cliente
limita llamadas a cinco segundos; frames iniciados y operaciones del helper
mantienen límites de tres segundos. Un intercambio perdido, inválido o vencido
cierra el cliente. No reintenta mutaciones automáticamente ni fabrica recibos.

`ConnectV2`/`ServeV2` requieren transporte previamente autenticado por el assembly.
Los wrappers Unix reutilizan metadata y credenciales del kernel; los heredados
comparan PID/UID/GID esperados. SO_PEERCRED de socketpair identifica al creador,
no a cada poseedor posterior del FD. Siguen siendo obligatorios los guards de
procedencia, supervisor, alias, namespace y privilegios del receptor existente.
No se activan children de `localruntime`. La exclusión entre procesos helper,
una autoridad/realm únicos y el cutover operativo siguen siendo gates separados.
No cambia la auditoría protegida, autoridad de exportación ni reservas físicas.

Reproducción Linux/WSL con Go 1.27.4 y dependencias offline:

```sh
GOPROXY=off GOSUMDB=off go test -race -buildvcs=false ./internal/firewallipc ./internal/previewruntime ./internal/nftguardian -count=3 -timeout=5m
go vet ./internal/firewallipc ./internal/previewruntime ./internal/nftguardian
go build ./cmd/... ./internal/...
```

Las pruebas utilizan sockets Unix privados y heredados reales, guardian real y
motores simulados. Cubren bootstrap, recuperación, expiración, reenlace corto,
sustitución de leases, observación obsoleta, respuestas perdidas, framing, peers,
Local-In, admisión en ráfaga y limpieza al fallar el listener. No prueban efectos
reales del kernel/listeners, reinicio del SO, cortes eléctricos ni paridad
desplegada. Métricas Debian y activación quedan pendientes de cualificación.
Antes de activar, revertir consiste en retirar código preparado sin consumidores;
un cutover futuro no autoriza volver a escritores v1 con trabajo sin resolver.

La cualificación Debian13 pasó codec/cliente, sesión y snapshot atómico con sockets Unix reales, UID1000, sin capacidades y red privada. CPU combinada0,057439s/pico cgroup9.887.744B; motores simulados. El fixture usa nombres temporales cortos para respetar el límite AF_UNIX. No acredita nftables real, listeners del appliance ni activación del runtime.
