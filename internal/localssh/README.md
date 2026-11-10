# Restricted ANDEIVA SSH transport

This internal server uses `golang.org/x/crypto/ssh` and the existing authentication
manager and local-service coordinator. It does not configure the host SSH service,
start a shell, execute processes, provision accounts or replace the transaction
engine. Loopback integration tests exercise actual encrypted SSH with verified
host keys; their backend double does not prove native policy enforcement.

The runtime creates one server per actual managed SSH listener. Supply its trusted
`localpolicy.Listener`, canonical envelope `ActivationHash`, provisioned Ed25519
host signer, shared `adminauth.Manager`, `Backend`, protected audit callback and
one shared `NewLimits()` across all SSH listeners. `Serve` verifies the actual
bound address/port. The caller must independently verify namespace, interface,
source policy, descriptor ownership and activation provenance. These properties
cannot be supplied by an SSH client or inferred from an address alone.

`ActivationHash` identifies the listener's applied revision. Replacing or changing
the policy must retire old servers and connections; never relabel an old server
with a new hash. Managed proof admission also requires the coordinator's active
pending tuple. An authenticated connection to an old listener is not proof of
access under a newer source policy. Recovery proof still comes from the separate
fixed authenticated recovery endpoint, not from this managed SSH listener.

Authentication uses the existing randomly provisioned 256-bit credential through
the SSH password method. It is not a human password or the future setup wizard's
password scheme. There is no public-key user login, interactive shell or MFA claim
in this bounded transport. Host authentication uses a provisioned Ed25519 key;
clients must pin that key through a trusted channel. No host-key verification bypass
is used by the integration tests. Transport algorithms come from the maintained
library's `SupportedAlgorithms`, with no insecure fallback list.

An explicit second authentication mode accepts `session:<opaque HTTPS bearer>`
through the encrypted SSH password method, after the client verifies the host key.
It requires the exact authenticated username and a currently valid recovery HTTPS
session. It reuses that session's hash so recovery proofs remain session-bound;
the SSH server neither exports the bearer/hash nor logs out the borrowed session
on close. Malformed, revoked or wrong-user sessions and credentials presented as
session tokens are rejected without falling back to ordinary login. Revalidation
occurs before each operation and after reading input. Clients must keep the bearer
out of command arguments, logs and persistent storage.

The password callback creates only a provisional auth session. The server binds a
domain principal after completed SSH authentication, rechecks the live session
before backend dispatch and after reading JSON, and logs out owned sessions on
every exit, including a failed handshake. `SessionHash` hashes the private auth token; tokens
are never returned through this transport. Endpoint identity and activation hash
come exclusively from server options. Administrators can use all commands;
viewers can use status/effective only. The coordinator performs its own admission,
ownership, generation, proof and role checks again.

## Closed command grammar

Each connection accepts one `session` channel and one exact `exec` command:

| Command | Standard input |
| --- | --- |
| `andeiva local-services status` | None |
| `andeiva local-services effective` | `localadmin.Filter` JSON object; `{}` selects all |
| `andeiva local-services history` | `{"before":0,"limit":100}`; limit 1–100 |
| `andeiva local-services audit` | None |
| `andeiva local-services proof` | `localadmin.ProofRequest` JSON object |
| `andeiva local-services execute` | `localadmin.Request` JSON object |

JSON input must finish with EOF and is limited to 64 KiB. Unknown fields, trailing
documents, null and oversized input are rejected. Transaction operation, revision,
generation, candidate, confirmation window and proofs retain their shared domain
meaning. Standard output is `{"data":<typed result>}` or
`{"error":<stable error code>}`, followed by a newline. Success exits 0; handled
command errors exit 2. Protocol rejection or connection closure can instead yield
a transport error. Output is limited to 1 MiB; internal error text is never sent.

Transactions requiring recovery proofs use the explicit borrowed-session mode.
The independent recovery HTTPS endpoint issues proofs for the same authenticated
session; an unrelated session for the same actor is insufficient. The ordinary
random-credential mode has its own session and supports reads, staging/validation
and managed endpoint proofs, but cannot replace the required recovery proof.
The coordinator detaches an admitted operation from connection cancellation under
its bounded deadline, so retiring the initiating listener does not abort the
transaction solely because its reply channel closed. Durable replay reconciles
the result. Loopback tests exercise real coordinator commit, confirm, save and
rollback with real SSH endpoint proofs and a simulated policy executor; they do
not claim native rules or listener lifecycle acceptance.

No whitespace normalization, shell expansion, arguments outside this grammar or
command forwarding is performed. Shell, PTY, environment, subsystem/SFTP, SCP,
agent forwarding, TCP/stream forwarding, global requests and additional channels
are rejected. There is no arbitrary operating-system execution path. An ordinary
interactive `ssh appliance` session is therefore unsupported; use an explicit
ANDEIVA command without PTY or environment requests. User-facing clients retain
responsibility for localized EN/ES/PT presentation of machine-readable results.

## Bounds and lifecycle

All instances share limits of 32 connections and four handshakes. Authentication
allows three attempts per connection and retains the existing manager's global
rate/session limits. Handshake deadline is five seconds; the command connection
deadline is fifteen seconds, including input/output. These fixed limits do not
extend a configuration lease. The deadline can close a connection whose mutation
was already accepted; callers must reconcile using the unchanged idempotency key.

`Stop` retires the listener, cancels backend contexts and closes accepted
connections without waiting for handlers. Activation callbacks must use `Stop`,
because the change may originate inside that listener's own SSH command. Calling
`Close` synchronously from such a callback would wait on itself. After the callback
returns, the lifecycle owner calls `Close` to join server workers and SSH connection
termination. Backend methods must honor cancellation. Merely closing the listening
socket is insufficient: established sessions must also be retired. The shared auth manager and
audit sink are owned by the runtime and remain available until server shutdown
completes. Protected audit failure closes the server. Audit records use fixed
actions/results and authenticated actor names, never raw commands, JSON bodies,
credentials, tokens or private host keys.

Run focused checks with the repository's Go toolchain:

```sh
go test -race ./internal/localssh
go vet ./internal/localssh
```

Tests cover real SSH authentication/host verification, provisional-session cleanup,
viewer denial, fixed server context, command/channel restrictions, bounded input,
revocation during input, deadlines, capacity and shutdown. Native namespace
HTTPS/SSH reachability, joint rule/listener rollback and appliance CPU/RAM remain
separate integration gates. This package is not production or host-SSH acceptance.

## Español

Transporte SSH restringido con autenticación real y comandos ANDEIVA exactos.
Usa la credencial aleatoria existente; no implementa contraseñas humanas, MFA ni
shell interactiva. El cliente debe verificar la clave de host. Rechaza PTY,
variables de entorno, SCP/SFTP, forwarding y comandos arbitrarios. JSON de entrada
máximo 64 KiB; salida máxima 1 MiB. Comparte límites de 32 conexiones y cuatro
handshakes; plazos de cinco y quince segundos. Al deshabilitar el listener hay que
cerrar el servidor y sus sesiones. Las pruebas loopback no prueban aplicación de
políticas en namespaces ni preparación para producción. La integración nativa y
las mediciones del appliance siguen siendo requisitos pendientes.
Para transacciones con prueba de recuperación, el modo explícito
`session:<bearer HTTPS>` reutiliza una sesión HTTPS válida del mismo usuario;
se verifica antes de cada operación y no se cierra al terminar SSH. Nunca exponga
el bearer en argumentos, logs o almacenamiento persistente. Una sesión distinta
del mismo usuario no sustituye la vinculación requerida.

## Português

Transporte SSH restrito com autenticação real e comandos ANDEIVA exatos. Usa a
credencial aleatória existente; não implementa senhas humanas, MFA nem shell
interativa. O cliente deve verificar a chave do host. Rejeita PTY, variáveis de
ambiente, SCP/SFTP, forwarding e comandos arbitrários. Entrada JSON limitada a
64 KiB; saída a 1 MiB. Limites compartilhados de 32 conexões e quatro handshakes;
prazos de cinco e quinze segundos. Ao desabilitar o listener, encerre o servidor
e suas sessões. Os testes loopback não comprovam aplicação de políticas em
namespaces nem prontidão para produção. Integração nativa e medições no appliance
continuam sendo requisitos pendentes.
Para transações com prova de recuperação, o modo explícito
`session:<bearer HTTPS>` reutiliza uma sessão HTTPS válida do mesmo usuário;
é verificada antes de cada operação e não é encerrada ao finalizar SSH. Nunca
exponha o bearer em argumentos, logs ou armazenamento persistente. Outra sessão
do mesmo usuário não substitui a vinculação exigida.
