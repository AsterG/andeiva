# Isolated local-services validation

## English

Observed on 2026-11-10 in an authorized Debian 13 AMD64 VMware laboratory
(2 vCPU, 4 GiB RAM). The runtime used production sources through `9ce658d`;
subsequent confirmation-test changes affect tests only. Runtime binary SHA-256:
`8c2f3946134617e7ea6b024e67758d171322b6b02427ef19b78db6a7bf8f5f55`.
Private credentials, raw reports, host inventory and screenshots are not distributed.

| Scenario | Observed result |
| --- | --- |
| Web administration | Create, edit ports/source CIDRs, validate, commit confirmed, endpoint confirmation, save, historical rollback and disable passed against real HTTPS/SSH listeners. |
| CLI/API | Complete transaction cycles and concurrent administrators passed; 10 exact status comparisons and 93 coherent state observations across the reviewed cycle/fault reports. |
| Authorization | Anonymous Web requests returned 401; viewer writes returned 403. API denied viewer changes/history and preserved the configuration. |
| Deadline | An unconfirmed change restored its verified predecessor after the returned deadline. This is not a precision measurement of timer duration. |
| Process faults | API kill, helper kill and API suspension during a pending commit recovered through an owned-fixture reset. Suspension acknowledgement preceded the deadline by 29.02 s. |
| Traffic after recovery | 28 authenticated HTTPS/SSH probes, 12 timeouts from unauthorized sources and four timeouts to retired pending-revision ports, across IPv4/IPv6, with positive controls and expected revision hashes. |
| Disable | Zero effective managed rules/listeners; four probes to retired HTTPS/SSH bindings timed out while the fixed recovery endpoint remained available. Running and Startup retained the disabled service definitions. |
| Browser presentation | Real browser captures in EN/ES/PT, Light/Dark and desktop/mobile; original logo unchanged. No mocked requests or TLS-validation bypass. |
| Cleanup | Owned processes and recovery listener stopped; host nftables and all route tables unchanged. Interface identity/address data unchanged apart from DHCP lifetime values. Installed Alpha and host SSH stayed active. |

Earlier compiler/transport testing separately exercised 216 TCP/UDP probes,
including 96 IPv6 probes with cold neighbors. This does not imply a UDP-based
HTTPS or SSH administration protocol.

During a controlled 30.008 s idle interval after disabling managed services,
the six initially retained runtime processes consumed 0.75 CPU seconds, or
2.50% of one CPU. Their final summed RSS was 96,144 KiB and summed PSS 58,933 KiB.
These are process-set observations, not whole-VM totals, peak aggregate memory,
an enabled/disabled delta or a production capacity benchmark. The helper had only
NET_ADMIN; API capabilities were empty. The root supervisor and namespace holders
remained privileged. Binary size was 14,656,455 bytes; the built frontend directory
used 631,689 apparent bytes and the exercised journal directory 1,458,575 apparent
bytes. These are not allocated-block or installer-size measurements.

Two browser confirmation attempts missed the proof-transfer deadline and reverted;
the repeated runs passed after shortening test coordination, without extending
security deadlines. The first native API cycle exposed an unexpected reset;
collector stability, canceled readback and coherent revision observations were
corrected before the successful repetition. Tests and independent review also
covered SSH status stream closure and confirmation timing under filesystem load.

Remaining limits: this is an operator-run laboratory composition, not a permanent
appliance service or production firewall. Reset interrupts administration and
recreates the fixture; uninterrupted traffic/listener continuity is not proven.
Physical reboot, power loss, first-boot provisioning, host service migration and
performance qualification are not established by these runs. Fixed recovery is
required for administrative changes; remote endpoint proofs are currently supplied
explicitly. The first-boot wizard and other service engines remain unimplemented.

Reproduce with the [English procedure](docs/en.md). Unit/race tests, `go vet`,
security analysis and Linux builds passed locally; CI must be checked on the
specific PR head before integration. Privileged network tests run only in the
authorized VM, never on shared CI runners.

## Español

La validación del 10-11-2026 utilizó Debian 13 AMD64 en VMware, 2 vCPU y 4 GiB.
Web completó creación, edición de puertos/orígenes, validación, Commit Confirmed,
confirmación, Save, Rollback y desactivación sobre HTTPS/SSH reales. CLI/API
completaron sus ciclos, concurrencia y paridad: 10 comparaciones exactas y 93
observaciones coherentes en los reportes revisados. Accesos anónimos y escrituras
de lectores fueron rechazados. Las capturas reales cubrieron EN/ES/PT, ambos temas
y escritorio/móvil, conservando el logotipo y la validación TLS.

Tras matar API/helper o suspender API durante un commit pendiente, la recuperación
recreó la fixture. La suspensión se confirmó 29,02 s antes del vencimiento.
Veintiocho sondas autenticadas, 12 timeouts desde orígenes no autorizados y cuatro
timeouts a puertos retirados de la revisión pendiente verificaron
HTTPS/SSH IPv4/IPv6 con controles positivos. La desactivación dejó cero reglas y
listeners gestionados, conservó sus definiciones y el acceso fijo de recuperación;
cuatro sondas a los puertos retirados terminaron en timeout. Las reglas y rutas
del host permanecieron intactas; sólo variaron los tiempos de vida DHCP.

Muestra en reposo de 30,008 s: 0,75 s de CPU (2,50% de un núcleo), RSS sumada
96.144 KiB y PSS sumada 58.933 KiB para seis procesos iniciales. No son el consumo
total de la VM, un pico agregado ni una comparación habilitado/deshabilitado.
Binario: 14.656.455 bytes; frontend: 631.689 bytes aparentes; journal ejercitado:
1.458.575 bytes aparentes. API sin capacidades, helper sólo NET_ADMIN; supervisor
y procesos que retienen namespaces siguen privilegiados.

Dos intentos Web caducaron durante la transferencia de pruebas y revirtieron;
se repitieron correctamente sin ampliar plazos. Un reset inesperado inicial motivó
correcciones y una repetición satisfactoria. El reset interrumpe la administración:
no demuestra continuidad, reinicio físico, resistencia a cortes eléctricos,
instalación permanente ni preparación para producción. Wizard y demás motores
siguen sin implementar. Véase el [procedimiento español](docs/es.md); comprobar
Quality y Security del commit exacto antes de integrar. Evidencias privadas y
credenciales permanecen fuera del repositorio.

## Português

A validação de 10-11-2026 utilizou Debian 13 AMD64 no VMware, 2 vCPU e 4 GiB.
A Web concluiu criação, edição de portas/origens, validação, Commit Confirmed,
confirmação, Save, Rollback e desativação com HTTPS/SSH reais. CLI/API concluíram
seus ciclos, concorrência e paridade: 10 comparações exatas e 93 observações
coerentes nos relatórios revistos. Acesso anônimo e escrita por leitores foram
negados. Capturas reais cobriram EN/ES/PT, ambos os temas e desktop/mobile, mantendo
o logotipo original e a validação TLS.

Após encerrar API/helper ou suspender a API durante um commit pendente, a recuperação
recriou a fixture. A suspensão foi confirmada 29,02 s antes do prazo. Vinte e oito
sondas autenticadas, 12 timeouts de origens não autorizadas e quatro timeouts em
portas retiradas da revisão pendente verificaram HTTPS/SSH IPv4/IPv6
com controles positivos. A desativação deixou zero regras/listeners gerenciados,
preservou suas definições e o acesso fixo de recuperação; quatro sondas às portas
retiradas terminaram em timeout. Regras e rotas do host permaneceram intactas;
somente os tempos de vida DHCP variaram.

Amostra ociosa de 30,008 s: 0,75 s de CPU (2,50% de um núcleo), RSS somada de
96.144 KiB e PSS somada de 58.933 KiB para seis processos iniciais. Não representam
o total da VM, pico agregado ou diferença ativado/desativado. Binário: 14.656.455
bytes; frontend: 631.689 bytes aparentes; journal exercitado: 1.458.575 bytes
aparentes. API sem capabilities, helper somente NET_ADMIN; supervisor e processos
que retêm namespaces continuam privilegiados.

Duas tentativas Web expiraram durante a transferência de provas e reverteram;
as repetições passaram sem ampliar os prazos. Um reset inesperado inicial motivou
correções e repetição satisfatória. Reset interrompe a administração: não comprova
continuidade, reinicialização física, resistência à falta de energia, instalação
permanente ou prontidão para produção. Wizard e outros motores não foram
implementados. Consulte o [procedimento português](docs/pt.md) e verifique Quality
e Security no commit exato antes da integração. Evidências privadas e credenciais
permanecem fora do repositório.
