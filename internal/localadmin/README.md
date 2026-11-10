# Local-service management admission

This internal adapter shares the existing `configpoc.Service` coordinator and
journal. It adds no transaction engine, authentication provider, HTTP listener or
privileged executor. The trusted runtime supplies its fixed namespace inventory,
independent lease authority and actual rules/listeners observer. Unit-test doubles
are not evidence of native HTTPS, SSH or packet enforcement.

`New` receives an already recovered coordinator and takes exclusive ownership of
its management operations. Every write passes through `Execute`; transports must
not expose the coordinator directly. `Context` comes from authenticated server
state, including the actual accepting endpoint, actor, session hash and surface.
Never decode it from request JSON or use a caller-supplied endpoint header.

An already cancelled request is rejected. An authenticated admitted operation
retains its original deadline with a ten-second maximum, independently of later
connection closure. Retiring its own listener cannot cancel that transaction.
Lost responses require status/readback or exact durable replay, not a new key.

The outer request contains `transaction` (unchanged `configpoc.Request`),
`recovery_proof` and `endpoint_proofs`. Proofs are outside the durable request
fingerprint: an acknowledged exact replay remains valid after proof consumption
or process restart, while changing the transaction under the same key is rejected.
The optional core `AdmissionGuard.Check(Request, Snapshot, *Revision)` runs after
authorization, durable replay and managed preflight, before engine queries and
intent persistence. Inputs are detached copies; the third argument is the resolved
historical revision for rollback and nil otherwise. Guards must not reenter the
coordinator. Existing guards and legacy fingerprints are unchanged.

The local-only profile requires default deny and no forwarding rules, including
legacy schema 1/2 envelopes. Schema 3 uses its canonical local manifest, fixed
inventory, the IDs `https`/`ssh`, owner `management`, corresponding management
kinds, at most two services/interfaces, four bindings per service and sixteen
sources per binding. Each service has one TCP singleton endpoint above port 1023.
Missing services are disabled. `localnft.ValidateManaged` provides shared bounds;
the runtime compiler independently validates its immutable neighbor profile.

Only administrators write or read history/audit. Viewers read status/effective
state. Transports still enforce real authentication, session revocation, CSRF and
authentication audit. Invalid transport credentials are not fabricated as core
transaction events. Core authorizes authenticated transaction identities again.

## Recovery and endpoint proofs

`IssueProof` accepts `{generation,target,lease}` only after real endpoint
authentication. A recovery proof must originate at the independently protected
recovery endpoint. It expires after 20 seconds and binds the actor and exact
request session. A managed endpoint proof expires after 60 seconds; it binds the
same actor but may come from a newly authenticated HTTPS/SSH session. Endpoint IDs
are obtained from `BindingEndpointID` using actual trusted listener metadata.

All proofs are random one-use tokens, stored only as hashes in a process/run-local
map, capped at 256 entries. They bind the generation, full target revision and
lease. No caller controls TTL. For commit, rollback and save, lease is the request
key; for confirm it is the current `snapshot.pending.lease`. This lease identifier
is not an authentication credential. An authenticated adapter must expose it to
the pending owner/administrator so confirmation is possible; it may redact it
from viewer responses. Tokens and authentication secrets must never enter audit
or diagnostic output.

Commit, rollback, confirm and save require recovery proof. Confirm also requires
one proof for every enabled target binding; disabling all managed services needs
only recovery proof. The coordinator's pending deadline remains authoritative:
endpoint proof lifetime never extends a lease. Admission reserves fresh proofs;
Arm/Confirm consume them, and successful Save consumes its reservation. A reserved
proof remains eligible during that one admitted operation's journal I/O. Invalid
proofs do not latch recovery or call the helper. Proof issuance uses a separate
mutex and never enters the coordinator. Managed endpoint proofs are available
only after the coordinator publishes the exact pending generation, target and
lease. Their context includes `ActivationHash`, fixed in the actual HTTPS/SSH
handler instance created for that revision. It must never be copied from request
data or a mutable global current revision. A pre-change connection cannot attest
a future source-policy change merely because the listening address is unchanged.
Expiry is capped by the pending deadline; drift invalidates outstanding endpoint
proofs. Recovery challenges remain available without entering the coordinator.

Unknown Arm/Confirm outcomes or nonexact receipts block further writes until the
trusted runtime performs explicit recovery and creates a new adapter. Confirm
requires exact effective observation before and after the authority confirms.
An exact durable receipt/readback can reconcile a lost confirmation acknowledgement.
The runtime must make its `Engine.Current` reflect verified combined state, not a
cached desired hash. Boot/restart/expiry recovery remains the existing coordinator
and guardian's responsibility, including independent rollback while the API stops.

`Status` retains the real snapshot when observation fails, with
`effective.phase="unavailable"`, `recovery_required=true` and empty observed arrays.
It does not synthesize effective rules from desired configuration. Effective
filters match service/interface/protocol/port/source; source applies only to rules,
so listener results are empty when a source filter is present.

## Español

Adaptador interno sobre el coordinador y journal existentes, sin otro motor ni
autenticación simulada. Requiere inventario fijo, denegación predeterminada y cero
reglas de forwarding. Administrador escribe y consulta historial/auditoría;
viewer consulta estado efectivo. Las pruebas reales de recuperación duran 20 s y
las de endpoints 60 s, sin ampliar el plazo confirmado. Confirman identidad,
generación, revisión y lease; todos los bindings habilitados deben verificarse.
Una prueba inválida no llama al helper. Un resultado incierto bloquea escrituras.
Las pruebas de endpoints requieren la revisión pendiente publicada y la instancia
autenticada que la sirve; una conexión anterior no puede confirmar un cambio futuro.
Sin observación válida se conserva la configuración real y se declara estado
efectivo no disponible, sin inventar reglas. La integración nativa queda pendiente.

## Português

Adaptador interno sobre o coordenador e journal existentes, sem outro motor nem
autenticação simulada. Exige inventário fixo, negação padrão e nenhuma regra de
forwarding. Administrador escreve e consulta histórico/auditoria; viewer consulta
estado efetivo. Provas reais de recuperação duram 20 s e de endpoints 60 s, sem
estender o prazo confirmado. Vinculam identidade, geração, revisão e lease; todos
os bindings habilitados exigem verificação. Prova inválida não chama o helper.
Resultado incerto bloqueia escritas.
Provas de endpoints exigem a revisão pendente publicada e a instância autenticada
que a serve; uma conexão anterior não confirma uma alteração futura.
Sem observação válida, a configuração real é preservada e o estado efetivo fica
indisponível, sem regras inventadas. A integração
nativa permanece pendente.
