# Managed HTTPS transport

## English

`New(Options)` adapts the existing authenticated administration API to one managed
HTTPS binding. `Options` supplies the shared authentication manager, local-service
backend, trusted inventory, listener metadata, immutable activation revision,
provisioned certificate/private key, shared `Limits`, and optional static handler.
Its `Serve`, `Stop`, and `Close` methods satisfy `locallistener.Server`; a runtime
factory passes the listener and activation hash supplied by the listener manager.
No accounts, certificates, interfaces, firewall rules or privileged processes are
created by this package.

The origin and proof endpoint identity derive from the exact binding. The
activation hash cannot be replaced by request headers or subsequent global state.
The supplied certificate must be current, cover the binding IP, allow server
authentication and match its private key. The provisioning runtime owns certificate
trust/distribution and must keep the signer immutable. Clients must validate the
certificate against their provisioned trust roots. TLS 1.3 is mandatory; HTTP/1.1
avoids independent multiplexed stream budgets. The manager must verify the socket's
namespace/interface provenance and the applied source policy; matching its address
and port alone does not prove either condition.

All instances must receive the same `Limits`: at most 32 accepted connections and
16 active requests, with immediate rejection on saturation. Header/handshake,
read, write and idle deadlines are 3, 5, 15 and 30 seconds respectively; headers are
bounded by the standard HTTP server's configured 8 KiB limit and parsing allowance.
Existing API validation, authentication, RBAC, CSRF and audit remain authoritative.
HTTPS sessions belong to the shared authentication manager, not a listener, and
survive connection retirement until expiration or explicit revocation.

`Stop` closes active, idle and handshaking sockets without joining handlers. A
transaction can therefore retire its own listener without waiting for itself.
`Close`, called outside activation, waits up to 12 seconds for `Serve` and admitted
handlers. Errors and drain timeouts are returned, never converted into successful
cleanup. A timed-out backend may still be running; its request slot stays occupied
until it actually returns. The existing coordinator owns bounded transaction
completion and replay after a lost response. External dependencies must not be
released based on a failed drain.

Tests use real unprivileged loopback TLS with a generated test CA, and a backend
double for transport boundaries. They cover trust, TLS version, identity, RBAC,
CSRF, revoked sessions, shared saturation, handshake deadlines, self-retirement,
drain timeout and close errors. They do not establish Debian deployment, effective
firewall policy, real listener-manager rollback, or production resource capacity.
Run `go test -race ./internal/localhttps` and `go vet ./internal/localhttps`.

## Español

El adaptador reutiliza la API y autenticación existentes para un binding HTTPS.
Recibe inventario, certificado/clave, backend, revisión inmutable y límites
compartidos; no crea cuentas, interfaces, reglas ni procesos privilegiados.
El origen y la identidad de prueba derivan del binding exacto. TLS 1.3 es obligatorio
y el cliente debe validar la CA provisionada. El gestor verifica procedencia del
socket y política efectiva; dirección y puerto por sí solos no las demuestran.

Todas las instancias comparten un máximo de 32 conexiones y 16 solicitudes; los
plazos de cabeceras/handshake, lectura, escritura e inactividad son 3/5/15/30 s.
Se conservan RBAC, CSRF y auditoría existentes. `Stop` cierra conexiones sin esperar
el comando actual; `Close`, fuera de la activación, espera como máximo 12 s y
propaga errores. Un timeout no demuestra que el backend terminó: conserva su plaza
hasta retornar. Las sesiones compartidas no se revocan al retirar un listener.

Las pruebas usan TLS real en loopback sin privilegios, CA de prueba y backend
simulado para límites de transporte. Cubren confianza, identidad, RBAC, CSRF,
revocación, saturación, plazos y retirada del propio listener. No acreditan Debian,
reglas efectivas, rollback del gestor ni capacidad de producción. Ejecutar
`go test -race ./internal/localhttps` y `go vet ./internal/localhttps`.

## Português

O adaptador reutiliza a API e autenticação existentes para um binding HTTPS.
Recebe inventário, certificado/chave, backend, revisão imutável e limites
compartilhados; não cria contas, interfaces, regras ou processos privilegiados.
A origem e a identidade da prova derivam do binding exato. TLS 1.3 é obrigatório
e o cliente deve validar a CA provisionada. O gestor verifica a procedência do
socket e a política efetiva; endereço e porta, isoladamente, não as comprovam.

Todas as instâncias compartilham no máximo 32 conexões e 16 solicitações; os
prazos de cabeçalhos/handshake, leitura, escrita e inatividade são 3/5/15/30 s.
RBAC, CSRF e auditoria existentes permanecem obrigatórios. `Stop` fecha conexões
sem esperar o próprio comando; `Close`, fora da ativação, espera até 12 s e propaga
erros. Um timeout não comprova que o backend terminou: sua vaga permanece ocupada
até retornar. As sessões compartilhadas não são revogadas ao retirar um listener.

Os testes usam TLS real em loopback sem privilégios, CA de teste e backend simulado
para os limites de transporte. Cobrem confiança, identidade, RBAC, CSRF, revogação,
saturação, prazos e retirada do próprio listener. Não comprovam implantação Debian,
regras efetivas, rollback do gestor ou capacidade de produção. Executar
`go test -race ./internal/localhttps` e `go vet ./internal/localhttps`.
