# ALPHA-001 validation / Validación / Validação

2026-11-10 · Experimental preview · Debian 13 AMD64 · VMware · 2 vCPU · 4 GiB RAM

## Artifact / Artefacto / Artefato

| Field / Campo | Value / Valor |
|---|---|
| Package / Paquete / Pacote | `andeiva-firewall-preview_0.1.0~alpha8_amd64.deb` |
| Source / Fuente / Código-fonte | `8688f86ee3bc8c34fe13ce5a1871a8ba8cc3c1e0` |
| Bytes | `11400396` |
| SHA-256 | `d2583651611db131ceb4545c77a2cf196a6d933d34d9e456314381ea338d746c` |

## English

The scenarios below passed in the isolated laboratory. Final independent review
of the collected evidence remains pending. This report does not establish
production readiness or completion of all appliance acceptance gates.

- Two Linux package builds were byte-identical; both passed package static checks.
  Full regression race tests and vet passed. GoSec reported zero findings across
  72 files. Quality run `42819442046` and Security run `42819442057` passed for the
  source revision above.
- Alpha8 completed two full VM boots, restoring saved Startup rather than unsaved
  Running. Real TCP/UDP probes verified allow on port 18080 and deny on port 18081;
  reverse-direction traffic was also checked before reboot.
- The native harness passed API process termination/recovery and full service
  stop, owned-resource cleanup and start, with host network snapshots unchanged.
  Remove/reinstall preserved protected file hashes, permissions and identities;
  explicit startup restored health.
- The full Web transaction cycle and API/CLI parity were exercised on alpha7,
  including authentication/authorization rejection (401/403) and real deny
  observations. Alpha8 separately passed Web inspection and a normal CLI commit;
  the approved logo remained identical. This does not claim a repeat of every
  alpha7 transaction on alpha8.

The resource samples below cover only 2.027424695 seconds with client activity.
They are neither sustained-load benchmarks nor whole-appliance totals. Target
start to health took 10.482354582 seconds, including the network stability gate;
this is not OS boot time.

| Service | Memory sample (bytes) | CPU time increase (ns) |
|---|---:|---:|
| Namespace owner | 41439232 | 176000 |
| Policy helper | 11522048 | 50221000 |
| API | 10457088 | 9395000 |

Startup requires ten quiet seconds within thirty seconds. This heuristic does
not prove network configuration has finished; later host changes stop the preview
without modifying host routes. Exhausted API recovery leaves management degraded
while the helper retains the verified policy and confirmation deadline; operator
recovery is required, and an active target is not proof of readiness. API suspension
through lease expiry and helper loss during a pending lease were tested separately.
The combination of terminal API failure and pending lease expiry was not tested.

Traffic observations are bounded in-memory counter deltas, not connection logs;
API restart creates a new stream and interrupts observation history. Enforcement
is limited to isolated IPv4 TCP/UDP test traffic. Local Service Policy Manager and
multi-interface runtime integration remain pending. HA, power-loss resilience and
production operation are not validated. See the [runtime contract](README.md),
[operator guide](docs/en.md) and [traffic semantics](../../internal/firewalladmin/TRAFFIC.md).

## Español

Los escenarios siguientes pasaron en el laboratorio aislado. La revisión
independiente final de la evidencia recopilada sigue pendiente. Este informe no
acredita preparación para producción ni el cumplimiento de todos los criterios
de aceptación del appliance.

- Dos builds Linux del paquete resultaron idénticos byte a byte y pasaron los
  controles estáticos. Pasaron la regresión completa con detección de carreras
  y vet. GoSec informó cero hallazgos en 72 archivos. Quality `42819442046` y
  Security `42819442057` pasaron para la revisión de código indicada arriba.
- Alpha8 completó dos arranques completos de la VM y restauró Startup guardado,
  en lugar de Running sin guardar. Sondas TCP/UDP reales verificaron permiso en
  el puerto 18080 y denegación en 18081; también se comprobó tráfico en sentido
  inverso antes del reinicio.
- El harness nativo pasó la terminación y recuperación del proceso API y la
  parada completa, limpieza de recursos propios y arranque de servicios, sin
  cambios en las capturas de red del host. Remove/reinstall conservó hashes de
  archivos protegidos, permisos e identidades; el arranque explícito recuperó
  la disponibilidad.
- En alpha7 se probó el ciclo Web completo de transacciones y la paridad API/CLI,
  incluidos rechazos de autenticación/autorización (401/403) y observaciones
  reales de denegación. En alpha8 se verificaron por separado la interfaz Web y
  un commit normal por CLI; el logo aprobado permaneció idéntico. No se afirma
  haber repetido en alpha8 todas las transacciones de alpha7.

Las muestras siguientes abarcan sólo 2,027424695 segundos con actividad de un
cliente. No son benchmarks de carga sostenida ni totales de todo el appliance.
El arranque del target hasta disponibilidad tardó 10,482354582 segundos, incluido
el control de estabilidad de red; no es el tiempo de arranque del sistema operativo.

| Servicio | Muestra de memoria (bytes) | Incremento de tiempo CPU (ns) |
|---|---:|---:|
| Propietario de namespaces | 41439232 | 176000 |
| Helper de políticas | 11522048 | 50221000 |
| API | 10457088 | 9395000 |

El arranque exige diez segundos estables dentro de un máximo de treinta. Esta
heurística no demuestra que la configuración de red haya terminado; cambios
posteriores del host detienen la preview sin modificar sus rutas. Al agotarse la
recuperación de la API, la gestión queda degradada mientras el helper conserva
la política verificada y el plazo de confirmación. Se requiere recuperación del
operador; un target activo no demuestra disponibilidad. La suspensión de la API
hasta vencer el plazo y la pérdida del helper con una confirmación pendiente se
probaron por separado. No se probó la combinación de fallo terminal de API y
vencimiento de una confirmación pendiente.

Las observaciones de tráfico son deltas acotados de contadores en memoria, no
registros de conexiones. Reiniciar la API crea un nuevo flujo e interrumpe el
historial. La aplicación de reglas se limita a tráfico IPv4 TCP/UDP de prueba
aislado. La integración en runtime de Local Service Policy Manager y múltiples
interfaces sigue pendiente. No están validados HA, resistencia a cortes de
energía ni uso en producción. Consulte el [contrato de runtime](README.md), la
[guía de operación](docs/es.md) y la [semántica de tráfico](../../internal/firewalladmin/TRAFFIC.md).

## Português

Os cenários abaixo passaram no laboratório isolado. A revisão independente final
das evidências coletadas continua pendente. Este relatório não comprova prontidão
para produção nem o cumprimento de todos os critérios de aceitação do appliance.

- Duas builds Linux do pacote foram idênticas byte a byte e passaram nas
  verificações estáticas. A regressão completa com detecção de corridas e vet
  passou. GoSec registrou zero ocorrências em 72 arquivos. Quality `42819442046`
  e Security `42819442057` passaram para a revisão de código indicada acima.
- Alpha8 completou duas inicializações completas da VM, restaurando Startup salvo
  em vez de Running não salvo. Sondas TCP/UDP reais verificaram permissão na porta
  18080 e bloqueio na porta 18081; o tráfego no sentido inverso também foi
  verificado antes da reinicialização.
- O harness nativo passou nos testes de término e recuperação do processo API e
  de parada completa, limpeza dos recursos próprios e inicialização dos serviços,
  sem alterações nos registros do estado de rede do host. Remove/reinstall
  preservou hashes dos arquivos protegidos, permissões e identidades; a
  inicialização explícita recuperou a disponibilidade.
- O ciclo Web completo de transações e a paridade API/CLI foram testados no alpha7,
  incluindo rejeições de autenticação/autorização (401/403) e observações reais de
  bloqueio. No alpha8, a interface Web e um commit normal pela CLI foram verificados
  separadamente; o logo aprovado permaneceu idêntico. Não se afirma que todas as
  transações do alpha7 tenham sido repetidas no alpha8.

As amostras abaixo abrangem apenas 2,027424695 segundos com atividade de um cliente.
Não são benchmarks de carga sustentada nem totais de todo o appliance. O tempo
entre iniciar o target e obter disponibilidade foi de 10,482354582 segundos,
incluindo a verificação de estabilidade da rede; não é o tempo de inicialização
do sistema operacional.

| Serviço | Amostra de memória (bytes) | Aumento do tempo de CPU (ns) |
|---|---:|---:|
| Responsável pelos namespaces | 41439232 | 176000 |
| Helper de políticas | 11522048 | 50221000 |
| API | 10457088 | 9395000 |

A inicialização exige dez segundos estáveis dentro de um máximo de trinta. Essa
heurística não comprova que a configuração de rede terminou; alterações posteriores
no host interrompem a preview sem modificar suas rotas. Quando as tentativas de
recuperação da API se esgotam, a gestão fica degradada enquanto o helper mantém a
política verificada e o prazo de confirmação. É necessária a recuperação pelo
operador; um target ativo não comprova disponibilidade. A suspensão da API até
expirar o prazo e a perda do helper durante uma confirmação pendente foram testadas
separadamente. A combinação de falha terminal da API e expiração de uma confirmação
pendente não foi testada.

As observações de tráfego são deltas limitados de contadores em memória, não
registros de conexões. Reiniciar a API cria um novo fluxo e interrompe o histórico.
A aplicação de regras está limitada ao tráfego IPv4 TCP/UDP de teste isolado.
A integração ao runtime do Local Service Policy Manager e de múltiplas interfaces
continua pendente. HA, resistência a quedas de energia e operação em produção não
foram validados. Consulte o [contrato de runtime](README.md), o
[guia de operação](docs/pt.md) e a [semântica de tráfego](../../internal/firewalladmin/TRAFFIC.md).
