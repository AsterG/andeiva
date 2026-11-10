# Local listener and observation channels

The supervisor creates private inherited streams for two separate roles. One
connects the helper to the unprivileged listener manager; another connects the
helper to the supervisor's retained-process socket collector. The channel carries
typed operations only. It cannot select a PID, path, command, namespace or service
identity. Launch metadata pins run, API instance, generation, namespace and UID.

Requests and replies are bounded to 64 KiB. Sequence violations, malformed frames,
wrong identities, cross-role operations and timeouts close the channel. A worker
error returns a generic failure without inventing an observed state. The helper
must still reconcile the returned registry with the intended revision and actual
kernel sockets. A registry alone is not evidence of a live listener.

These streams are not public authentication endpoints. Their confidentiality and
peer identity require the supervisor's descriptor handoff and privilege checks.
That runtime wiring and native recovery remain acceptance gates. Pipe tests prove
framing and role separation, not Debian privilege separation or packet filtering.

## Español

Canales privados heredados: uno administra listeners sin privilegios y otro
consulta el collector de sockets del proceso retenido. No aceptan PID, rutas ni
comandos elegidos por el cliente. Identidad, generación y secuencia quedan fijadas;
errores de protocolo o timeout cierran el canal. El helper debe contrastar registro,
configuración y sockets reales. El cableado y la recuperación Debian siguen
pendientes; las pruebas de canal no demuestran filtrado real.

## Português

Canais privados herdados: um administra listeners sem privilégios e outro consulta
o coletor de sockets do processo retido. Não aceitam PID, caminhos ou comandos do
cliente. Identidade, geração e sequência são fixas; erros de protocolo ou timeout
fecham o canal. O helper deve reconciliar registro, configuração e sockets reais.
A integração e recuperação Debian continuam pendentes; testes de canal não
demonstram filtragem real.
