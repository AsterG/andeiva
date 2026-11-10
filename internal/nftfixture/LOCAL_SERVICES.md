# Local-service fixture

`NewLocalOwned` creates three owned network namespaces using the existing
descriptor-based lifecycle. It creates no persistent namespace names and changes
no host interface, route, ruleset or sysctl. Existing `New`/`NewOwned` keep their
forwarding experiment behavior; the local constructor has a separate allowlist.

The gateway has `src0` and `dst0`, each connected only to its own source/sink
namespace. IPv4 links are `198.18.1.0/29` and `198.18.2.0/29`; gateway `.1`, primary
peer `.2`, alternate peer `.3`. IPv6 links are `fd42:616e:6465:1::/64` and
`fd42:616e:6465:2::/64`, with the same host numbers. Explicit link-local pairs are
`fe80::1`/`fe80::2` and `fe80::5`/`fe80::6`. Automatic link-local generation is
disabled only on these owned veths. Static IPv6 fixture addresses use `nodad` to
avoid setup timing dependence; this fixture is not evidence of real DAD handling.

No transit/default route or forwarding activation is issued. A subprocess reads
the isolated gateway forwarding settings and refuses initialization if forwarding
is enabled. `LocalInventory` and `LocalNeighbors` return independent copies of
the exact trusted inventory/profile consumed by `localnft.CompileWithNeighbors`.
Both logical links are laboratory LANs, unrelated to host WAN/LAN roles.

`StartLocalServices` launches only the current trusted executable's fixed
`--local-services HOST_INODE SUPERVISOR_PID` role in the retained gateway namespace,
as the configured unprivileged UID/GID with all capabilities dropped and
`no-new-privileges`. Its implementation must call `GuardLocalServices` before
handling input. The existing `StartGateway` retains its separate, narrow guardian
role with NET_ADMIN. Neither API accepts an executable path from an administrator.

The constructor starts no listener. `StartLocalEcho` explicitly launches a
transport-test echo process on gateway IPv4/IPv6 addresses and ports 18080–18082
(TCP and UDP). This is not HTTPS, SSH, DNS or any other service implementation.
It exits on supervisor input closure and is retained for `CloseOwned` cleanup.
`ProbeLocalGateway` accepts only fixed side/family/primary-or-alternate/protocol/
test-port selectors. It binds the exact chosen source and exchanges a random
64-byte nonce with its directly attached gateway. It accepts no destination IP,
shell command, arbitrary port, or route. A timeout is a denied observation;
connection refusal and other local errors remain errors rather than policy proof.

Keep positive echo controls separate from real authenticated HTTPS/SSH tests.
`ClearLocalNeighbors` flushes IPv4/IPv6 neighbor caches on exactly the four owned
veths, only in local mode. Use it before claiming cold-neighbor coverage in an
authorized native test. Always compare host/sentinel baselines and run `CloseOwned` after stopping
the API/helper; it closes only retained processes and namespace handles.

Unprivileged verification:

```sh
go test ./internal/nftfixture
go test -race ./internal/nftfixture
go vet ./internal/nftfixture
```

Command-plan and parser tests do not execute namespace changes. Real traffic,
kernel readback, resource measurements and failure recovery require the authorized
Debian 13 laboratory and must be recorded separately.

## Typed process handoff

`LaunchLocalAPI`, `LaunchLocalHelper` and `LaunchLocalProbe` are additive laboratory
launchers. They accept already-open descriptors from the root supervisor, not
paths, shell strings or administrator-selected executables. They return only
after starting the fixed role of the already-validated executable. The API uses
the fixture's UID/GID; the helper requires a different non-root UID and GID and
receives only NET_ADMIN. Probes have no capabilities and enter only source/sink.
The existing forwarding and echo launchers keep their previous contract.

| Role | FD3 | FD4 | FD5 | FD6 | FD7 | FD8 |
| --- | --- | --- | --- | --- | --- | --- |
| API | Gateway namespace | LAN recovery TCP | Loopback recovery TCP | Transaction stream | Listener stream | Bootstrap pipe |
| Helper | Gateway namespace | Transaction stream | Listener stream | Collector stream | Bootstrap pipe | None |
| Probe | Selected client namespace | Bootstrap pipe | None | None | None | None |

Control descriptors must be connected Unix stream sockets; bootstrap must be the
read end of a pipe. Aliased descriptors, wrong types and missing slots are rejected.
Recovery descriptors must already listen on explicit, non-wildcard addresses and
ports above 1023. FD4 must not be loopback; FD5 must be loopback. The runtime must
separately validate the approved host interface, exact tuple, TLS and source ACL
before handing them over. The fixture does not authorize a LAN address, open that
host socket or change the host firewall.

The caller owns every supplied file. Successful `exec` duplicates the fixed map;
close the parent's child-side copies after launch while retaining any independent
recovery originals. Create all parent descriptors close-on-exec so no unrelated
file or secret channel can leak outside that map. Do not retain unnecessary
writers that prevent EOF. Fixture
cleanup retains and stops only its own processes and namespace descriptors.

Each child must call `GuardLocalAPI`, `GuardLocalHelper` or `GuardLocalProbe`
before opening or consuming inherited files. Guards check every required slot
before any `/proc` open, namespace type and identity, the root parent, exact
UID/GID/capability envelope, no-new-privileges, empty supplementary groups and
root-owned descriptors. Unix peer credentials identify the supervisor that
created the socketpair; the higher-level channel still pins the actual peer role,
run, instance and generation. No guard substitutes for channel authorization.

The probe runner must bound and strictly decode its bootstrap, restrict all
destinations and operations to the fixed fixture and verify real HTTPS/SSH peer
identity. A typed process launch alone is not an authenticated traffic test.
Command-plan and descriptor tests run without privileges and do not establish
native isolation, recovery or resource usage. Those remain Debian acceptance gates.

### Español

Los nuevos launchers aceptan descriptores ya abiertos por el supervisor root,
nunca rutas o comandos del administrador. API y helper usan UID/GID distintos;
sólo el helper recibe NET_ADMIN. La tabla define posiciones fijas: sockets Unix
conectados, bootstrap por pipe de lectura y recuperación TCP en direcciones
explícitas. El runtime valida interfaz LAN autorizada, puerto, TLS y orígenes.
No se abren sockets del host ni se modifica su firewall desde este componente.

El padre conserva la propiedad de los archivos y cierra las copias para hijos
después del lanzamiento. Cada hijo ejecuta su guard antes de abrir archivos o
leer bootstrap; se rechazan slots ausentes, tipos incorrectos, alias y privilegios
excesivos. Las pruebas sin privilegios no demuestran aislamiento ni recuperación
en Debian. Los probes reales deben validar certificados o claves SSH y limitarse
a los destinos de la fixture.

### Português

Os novos launchers recebem descritores já abertos pelo supervisor root, nunca
caminhos ou comandos do administrador. API e helper usam UID/GID distintos;
somente o helper recebe NET_ADMIN. A tabela fixa as posições: sockets Unix
conectados, bootstrap por pipe de leitura e recuperação TCP em endereços explícitos.
O runtime valida interface LAN autorizada, porta, TLS e origens. Este componente
não abre sockets do host nem modifica seu firewall.

O pai mantém a propriedade dos arquivos e fecha as cópias destinadas aos filhos
após iniciar os processos. Cada filho executa seu guard antes de abrir arquivos
ou ler bootstrap; slots ausentes, tipos incorretos, aliases e privilégios excessivos
são rejeitados. Testes sem privilégios não comprovam isolamento ou recuperação
no Debian. Probes reais devem validar certificados ou chaves SSH e limitar-se aos
destinos da fixture.
