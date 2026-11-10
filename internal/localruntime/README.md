# Isolated local-services runner

Operator procedures: [English](docs/en.md), [Español](docs/es.md),
[Português](docs/pt.md).

## English

Experimental composition for the explicitly authorized Debian 13 AMD64 laboratory.
It reuses one configuration coordinator/journal, the Local-In engine, independent
rollback guardian, real HTTPS/SSH transports and retained-process socket collector.
No installed preview service, host firewall, routes or host SSH/HTTPS are changed.
Native integration and resource qualification remain pending; unit tests do not
establish effective packet filtering or production readiness.

The root supervisor creates exactly three owned namespaces. API and helper accounts
must already exist with different nonzero primary UIDs/GIDs, nologin shells and no
supplementary groups. The API has no capabilities; the helper has only NET_ADMIN.
The supervisor is privileged and records its actual effective capabilities in the
root-only `check` result. Cross-UID collector access may depend on those privileges;
there is no claim that the supervisor lacks SYS_PTRACE.

Provision an absolute `/var/tmp/andeiva-local-<8..40 lowercase characters>` directory
with a root-owned 0600 JSON input. Configuration fields are `lan_address`,
`lan_interface`, `allowed_cidr`, `api_user`, `api_group`, `helper_user`,
`helper_group`, and `web_root` (a root-owned built frontend directory).
The LAN source prefix is explicit and independent of the listener address. LAN and
loopback recovery bind separately to port 18443; an occupied port fails startup.
There is no wildcard, WAN selection or fallback to an installed service.

```sh
andeiva-local-lab provision /var/tmp/andeiva-local-example01 /root/lab-config.json
andeiva-local-lab run --snapshot-confirmed /var/tmp/andeiva-local-example01
# From another authorized root console:
andeiva-local-lab check /var/tmp/andeiva-local-example01
andeiva-local-lab probe /var/tmp/andeiva-local-example01 /root/request.json /root/new-result.json
andeiva-local-lab fault /var/tmp/andeiva-local-example01 api-kill
andeiva-local-lab reset /var/tmp/andeiva-local-example01
andeiva-local-lab stop /var/tmp/andeiva-local-example01
```

Provisioning creates no OS accounts and never regenerates existing credentials.
Operator files reside in `operator/{admin-a,admin-b,viewer}.json` (root 0600).
CA, accounts, TLS private key and SSH host key are root-owned and readable only by
the API group. The helper cannot traverse the data directory. Auth audit appends
and fsyncs with an 8 MiB budget; exhaustion blocks authentication and preserves
the file. Existing partial provision or invalid ownership requires operator review.

`probe` input and output paths are absolute; input must be root 0600 and output must
not exist. Its JSON fields are `side` (source/sink), `family` (ipv4/ipv6), `origin`
(primary/alternate), `protocol` (https/ssh), `port` (high TCP port), `operation`
(status/effective/proof/execute), `username`, and optional `session`, `proof` or
`transaction`. Targets derive only from the fixed fixture inventory. Results are
`{status,data,error}` written exclusively to the protected output file. Proof
tokens and sessions must never enter screenshots or evidence logs. Without an
explicit borrowed session, root obtains and revokes a temporary recovery session;
long-lived credentials never enter the probe process. Shared API/probe UID is not
claimed to isolate temporary sessions from the API itself. TLS CA and SSH host-key
validation are mandatory. TIMEOUT, REFUSED, TLS, HOSTKEY, AUTH and PROTOCOL failures
remain distinct; a generic failure is not evidence of policy denial.

Fault controls are restricted to retained children: api-kill, helper-kill,
api-pause and api-resume. Process/channel loss or a blocked guardian closes the
owned fixture before recreation; at most three resets occur in a 60-minute run.
This interrupts management and is not dataplane continuity. Run/Instance and
namespace generation change on reset; rollback without reset preserves those
identities. Same-boot reconstruction reconciles durable Running/pending with
`Boot:false`; a valid changed OS boot ID selects Startup. A missing marker with
existing journal data, or a malformed marker, blocks recovery. The recovery
listening descriptors remain held by the supervisor, but authenticated HTTP
availability requires a healthy recovered API process.

Descriptor map: API FD3 namespace, FD4 LAN recovery, FD5 loopback recovery, FD6
transactions, FD7 listener control, FD8 bootstrap; helper FD3 namespace, FD4
transactions, FD5 listener control, FD6 collector, FD7 bootstrap. Private streams
are CLOEXEC socketpairs with fixed typed roles. Child-side copies close immediately
after launch; guards run before reading or duplicating them. The collector channel
is served only by the root supervisor and pins the directly owned API process.

Managed HTTPS shares 32 connections/16 requests; SSH shares 32 connections/four
handshakes. Recovery reserves 16 connections/eight requests across its two sockets.
Protocol deadlines and bounded drains remain authoritative. Native cold-neighbor,
permission, reset, failed confirmation and resource tests are still required.

## Español

Runner experimental para el laboratorio Debian 13 AMD64 autorizado. Reutiliza un
solo coordinador/journal y protocolos HTTPS/SSH reales en tres namespaces propias;
no modifica Alpha ni SSH/HTTPS, rutas o firewall del host. El supervisor es root y
registra sus capacidades reales; API sin capacidades, helper sólo NET_ADMIN y
cuentas nologin distintas sin grupos adicionales. No se afirma ausencia de
SYS_PTRACE en el supervisor ni validación nativa completada.

Los comandos y campos anteriores son idénticos en todos los idiomas. Configuración
y solicitudes privadas root 0600; resultados de probe nuevos root 0600, sin tokens
en logs. La credencial duradera permanece en root; los probes usan sesiones
temporales revocadas o una sesión prestada explícita. Un timeout, rechazo TCP,
fallo TLS, host key, autenticación o protocolo no son resultados intercambiables.

Reset cierra y recrea únicamente la fixture, hasta tres veces: interrumpe gestión,
no ofrece continuidad. Mismo boot conserva/reconcilia Running y pending; nuevo boot
válido carga Startup. Marcador corrupto o ausente con journal bloquea recuperación.
La recuperación fija usa LAN y loopback en 18443; su disponibilidad autenticada
requiere API saludable. Auditoría protegida con presupuesto de 8 MiB sin borrado
automático. Pruebas de tráfico, fallos y recursos nativos siguen pendientes.

## Português

Runner experimental para o laboratório Debian 13 AMD64 autorizado. Reutiliza um
único coordenador/journal e HTTPS/SSH reais em três namespaces próprias; não altera
Alpha nem SSH/HTTPS, rotas ou firewall do host. O supervisor é root e registra suas
capacidades reais; API sem capacidades, helper somente NET_ADMIN e contas nologin
distintas sem grupos adicionais. Não há alegação de ausência de SYS_PTRACE no
supervisor ou de validação nativa concluída.

Os comandos e campos acima são iguais em todos os idiomas. Configuração e pedidos
privados root 0600; resultados novos de probe root 0600, sem tokens nos logs. A
credencial duradoura permanece em root; probes usam sessões temporárias revogadas
ou uma sessão explicitamente emprestada. Timeout, recusa TCP, erro TLS, host key,
autenticação e protocolo são resultados distintos.

Reset fecha e recria apenas a fixture, até três vezes: interrompe a gestão, sem
continuidade garantida. Mesmo boot preserva/reconcilia Running e pending; novo boot
válido carrega Startup. Marcador inválido ou ausente com journal bloqueia a
recuperação. Recuperação fixa usa LAN e loopback em 18443; disponibilidade
autenticada exige API saudável. Auditoria protegida com orçamento de 8 MiB sem
remoção automática. Testes nativos de tráfego, falhas e recursos permanecem pendentes.
