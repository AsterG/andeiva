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

El coordinador conserva las autoridades exclusivas Pending.Deadline y Boot
Started + 10 s. `RecoverPreviousUntil` recupera el recibo caducado exacto tras
reiniciar el adaptador, sin adoptar otro plazo del helper.

La composición preparada puede optar por `v2CoordinatorOptions.GuardDeadlines`.
Commit/Rollback/Recover inmediatos seleccionan `Intent.guard_deadline` opcional y
la feature persistente `configuration.guard-deadline.v1` atómicamente antes de
los efectos. La ventana de diez segundos comienza tras validar y justo antes de
seleccionar Intent; nunca se deriva de Accepted/ExecuteBefore ni Clock. No se
añaden campos a las solicitudes ni una activación pública.

La activación en frío rechaza Intents inmediatos antiguos sin plazo original.
Los lectores anteriores rechazan la feature y los nuevos exigen conservar la
opción. Pending y Boot no admiten una segunda autoridad temporal. PlanIntent y el
archivo tipado conservan el plazo exacto. R2 mantiene sus límites 16 MiB/64 inodos,
128 KiB de núcleo y 256 KiB por objeto; la admisión contabiliza el nuevo espacio
antes de reclamar reservas físicas.

Sin optar por ello, el rechazo inmediato ocurre antes de objetos/Intent/efectos,
conservando la operación ya admitida como aceptada y el almacén disponible. La
composición relativa heredada no cambia. Una confirmación ambigua ya completada
en el helper conserva la barrera de recuperación, sin rollback ciego ni Running
ficticio. No se activa el runtime ni se acredita tráfico real o corte eléctrico.
