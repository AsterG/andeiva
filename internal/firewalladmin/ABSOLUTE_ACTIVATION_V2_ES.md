# Plazos absolutos preparados del helper

Los verbos internos v2 `arm_until`, `apply_scoped` y `confirm_scoped` conservan
el plazo UTC canónico exacto. Aplicación, confirmación y recuperación comparan
ID, hashes y plazo dentro del mutex del guardian. Un plazo distinto por 1 ns
identifica otro recibo y no autoriza ninguna acción.

`NewPreparedAbsoluteGuardedEngine` exige una autoridad absoluta tipada completa.
El adaptador relativo no incorpora `ArmUntil`; no existe fallback a TTL relativo.
Los helpers anteriores rechazan los verbos nuevos. No se activa el runtime ni se
añaden campos públicos Web/CLI/API.

La lectura lenta consume el tiempo restante. El guardian deriva una expiración
monotónica independiente después de esa lectura. Una nueva reserva requiere
500 ms como mínimo; volver a vincular un recibo exacto existente puede hacerse
con menos tiempo sin renovarlo. Cancelar/desconectar el controlador no cancela
el temporizador. Reiniciar el controlador conserva la reserva del helper;
reiniciar el helper pierde su estado RAM y exige recuperación journal/bootstrap.

Reproducción: ejecutar `go test -race` y `go vet` sobre `./internal/nftguardian`,
`./internal/firewalladmin`, `./internal/firewallipc`, `./internal/previewruntime`,
y `go build ./...`. Las pruebas Linux usan sockets sin privilegios y motores SIM.
No acreditan nftables real, cortes eléctricos, integración Boot ni producción.
