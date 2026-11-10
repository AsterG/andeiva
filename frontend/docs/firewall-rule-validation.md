# Firewall rule validation · Validación · Validação

## English

**2026-11-10 — observed laboratory scenarios passed; final combined CI remains pending.**
These results cover the schema-4 backend change `0717159` and firewall frontend
`c9c6a5e`, including the firewall-scoped CSS adjustments used in the browser run.
They describe an isolated Debian laboratory with three network namespaces, two
IPv4 TCP/UDP rules and real authenticated HTTPS administration. They do not
constitute production acceptance.

### Transactions and effective traffic

The API/official CLI scenario completed **86 checks, 32 real probes** (6 allowed,
26 denied) and **8 exact ruleset readbacks** across two sequential fixtures. It
created disabled rules, staged and validated them, committed and saved them,
enabled them through CLI, confirmed and saved, and requested a 30-second
confirmation lease. Restoration was verified after the returned deadline;
timer precision was not measured. Historical rollback restored disabled rules and
then the original schema-2 revision. An API restart preserved unsaved Running;
a fresh fixture using the same journal restored saved Startup.

The combined browser run completed four checkpoints, each correlated with API,
official CLI, exact effective rules and real TCP/UDP probes:

| Checkpoint | Observed state | Port 18080 |
| --- | --- | --- |
| Disabled and saved | Two persisted disabled rules; no effective rule counters | Denied |
| Enabled, confirmed and saved | Both rules active; Running equals Startup | Allowed |
| Dragged order committed | New Running order; Startup retains its saved order | Allowed |
| Historical rollback | Disabled revision restored; final Save subsequently verified | Denied |

Port 18081 remained denied. The browser controller recorded **41 checks,
16 probes** (4 allowed, 12 denied) and **5 exact ruleset readbacks**. Denial probes
included a positive listener-health control. Active rules produced fresh counter
deltas; disabled revisions had no active rule records. Light and Dark captures
covered the editor, saved disabled rules and unsaved reordered Running state.
The browser used real TLS validation and authentication, without mocked responses
or a certificate-validation bypass.

The first browser attempt, run 001, failed when manual checkpoint transfer
exceeded the coordination deadline. It is not counted as a pass. Run 002 used
automated transfer and completed the four checkpoints, final Save and logout.
Browser and controller reports were correlated; checkpoint files alone are not
independent browser attestation. The three successful fixtures recorded
successful cleanup and unchanged host state under the existing laboratory checks.

### Resource observations and limits

| Fixture | Elapsed seconds | Supervisor CPU seconds | Child CPU seconds | Maximum child RSS, KiB |
| --- | ---: | ---: | ---: | ---: |
| API/CLI first fixture | 54.678599351 | 0.124264 | 2.769029 | 18,100 |
| API/CLI fresh fixture | 6.951193177 | 0.049182 | 0.718900 | 17,100 |
| Combined browser fixture | 90.801095849 | 0.064060 | 2.245907 | 18,988 |

A browser renderer sample over 3.00208119 seconds measured 0.009948 seconds of
task time, 4,654,556 bytes of used JavaScript heap and 6,955,008 bytes allocated.
These are bounded scenario measurements: maximum child RSS is not total appliance
memory, and renderer heap is not browser RSS or a capacity benchmark.

The installed Alpha appliance was not updated. Fresh-fixture recovery is not an
OS reboot, power-loss or uninterrupted dataplane test. IPv6, large policies,
long-duration load and production readiness are outside this evidence. Final CI
and release review remain separate gates. See the [operator guide](../src/firewall/docs/rules-en.md).

## Español

**2026-11-10 — escenarios observados aprobados en laboratorio; CI final del conjunto pendiente.**
Los resultados cubren el backend de esquema 4 `0717159` y el frontend de firewall
`c9c6a5e`, incluidos los ajustes CSS limitados al firewall utilizados en la prueba
del navegador. El laboratorio Debian usa tres namespaces de red, dos reglas
IPv4 TCP/UDP y administración HTTPS real autenticada. No es una aceptación para
producción.

### Transacciones y tráfico efectivo

El recorrido API/CLI oficial completó **86 comprobaciones, 32 sondas reales**
(6 permitidas, 26 denegadas) y **8 lecturas exactas del ruleset** en dos entornos
aislados consecutivos. Creó reglas deshabilitadas, preparó y validó la candidata,
aplicó y guardó, habilitó mediante CLI, confirmó y guardó; además verificó la
reversión después del plazo devuelto para una confirmación solicitada de 30 segundos,
sin medir la precisión del temporizador. El rollback histórico
restauró las reglas deshabilitadas y después la revisión original de esquema 2.
Reiniciar la API conservó Running sin guardar; recrear el entorno con el mismo
registro persistente restauró Startup guardada.

La prueba combinada del navegador completó cuatro puntos de control, comparados
con API, CLI oficial, reglas efectivas exactas y sondas TCP/UDP reales:

| Punto de control | Estado observado | Puerto 18080 |
| --- | --- | --- |
| Deshabilitadas y guardadas | Dos reglas persistidas deshabilitadas; sin contadores efectivos | Denegado |
| Habilitadas, confirmadas y guardadas | Ambas activas; Running coincide con Startup | Permitido |
| Orden arrastrado y aplicado | Nuevo orden en Running; Startup conserva el guardado | Permitido |
| Rollback histórico | Revisión deshabilitada restaurada; guardado final verificado después | Denegado |

El puerto 18081 permaneció denegado. El controlador registró **41 comprobaciones,
16 sondas** (4 permitidas, 12 denegadas) y **5 lecturas exactas del ruleset**.
Las denegaciones incluyeron un control positivo de disponibilidad del listener.
Las reglas activas produjeron nuevos incrementos de contadores; las revisiones
deshabilitadas no tuvieron registros de reglas activas. Las capturas en Claro y
Oscuro cubrieron editor, reglas deshabilitadas guardadas y Running reordenada sin
guardar. El navegador utilizó TLS y autenticación reales, sin respuestas simuladas
ni omitir la validación de certificados.

El intento 001 falló porque el traslado manual de puntos de control excedió el
plazo de coordinación; no se contabiliza como aprobado. El intento 002 automatizó
el traslado y completó los cuatro puntos, guardado final y cierre de sesión. Se
correlacionaron los informes del navegador y del controlador; los archivos de
coordinación solos no son una prueba independiente del navegador. Los tres
entornos de las ejecuciones satisfactorias registraron limpieza correcta y estado del host sin cambios
según las comprobaciones existentes del laboratorio.

### Recursos observados y límites

| Entorno | Duración, segundos | CPU supervisor, segundos | CPU hijos, segundos | RSS máximo de un hijo, KiB |
| --- | ---: | ---: | ---: | ---: |
| Primer entorno API/CLI | 54.678599351 | 0.124264 | 2.769029 | 18,100 |
| Entorno API/CLI recreado | 6.951193177 | 0.049182 | 0.718900 | 17,100 |
| Entorno combinado con navegador | 90.801095849 | 0.064060 | 2.245907 | 18,988 |

Una muestra del renderizador de 3.00208119 segundos midió 0.009948 segundos de
ejecución de tareas, 4,654,556 bytes de heap JavaScript usado y 6,955,008 bytes
asignados. Son mediciones acotadas: el RSS máximo de un hijo no es la memoria
total del appliance, y el heap no es el RSS del navegador ni una prueba de capacidad.

No se actualizó la Alpha instalada. Recrear el entorno no equivale a reiniciar
el sistema operativo, probar pérdida de energía ni demostrar continuidad del
plano de datos. IPv6, políticas grandes, carga prolongada y preparación para
producción quedan fuera de esta evidencia. CI final y revisión de publicación
siguen siendo requisitos separados. Consulte la [guía operativa](../src/firewall/docs/rules-es.md).

## Português

**2026-11-10 — cenários observados aprovados no laboratório; CI final do conjunto pendente.**
Os resultados abrangem o backend de esquema 4 `0717159` e o frontend de firewall
`c9c6a5e`, incluindo os ajustes CSS restritos ao firewall usados no teste do
navegador. O laboratório Debian usa três namespaces de rede, duas regras IPv4
TCP/UDP e administração HTTPS real autenticada. Não é uma aprovação para produção.

### Transações e tráfego efetivo

O cenário API/CLI oficial concluiu **86 verificações, 32 sondagens reais**
(6 permitidas, 26 negadas) e **8 leituras exatas do conjunto de regras** em dois
ambientes isolados consecutivos. Criou regras desabilitadas, preparou e validou a
candidata, aplicou e salvou, habilitou pela CLI, confirmou e salvou; também verificou
a reversão depois do prazo retornado para uma confirmação solicitada de 30 segundos,
sem medir a precisão do temporizador. O rollback histórico
restaurou as regras desabilitadas e depois a revisão original do esquema 2.
Reiniciar a API preservou Running não salva; recriar o ambiente com o mesmo
registro persistente restaurou Startup salva.

O teste combinado do navegador concluiu quatro pontos de controle, comparados
com API, CLI oficial, regras efetivas exatas e sondagens TCP/UDP reais:

| Ponto de controle | Estado observado | Porta 18080 |
| --- | --- | --- |
| Desabilitadas e salvas | Duas regras persistidas desabilitadas; sem contadores efetivos | Negada |
| Habilitadas, confirmadas e salvas | Ambas ativas; Running corresponde a Startup | Permitida |
| Ordem arrastada e aplicada | Nova ordem em Running; Startup mantém a ordem salva | Permitida |
| Rollback histórico | Revisão desabilitada restaurada; salvamento final verificado depois | Negada |

A porta 18081 permaneceu negada. O controlador registrou **41 verificações,
16 sondagens** (4 permitidas, 12 negadas) e **5 leituras exatas das regras**.
As negações incluíram controle positivo de disponibilidade do listener. As regras
ativas produziram novos incrementos de contadores; as revisões desabilitadas não
tiveram registros de regras ativas. As capturas em Claro e Escuro cobriram editor,
regras desabilitadas salvas e Running reordenada não salva. O navegador usou TLS
e autenticação reais, sem respostas simuladas nem desativar a validação de certificados.

A tentativa 001 falhou porque a transferência manual dos pontos de controle
excedeu o prazo de coordenação; não é contabilizada como aprovada. A tentativa 002
automatizou a transferência e concluiu os quatro pontos, salvamento final e logout.
Os relatórios do navegador e do controlador foram correlacionados; arquivos de
coordenação isolados não são uma prova independente do navegador. Os três ambientes
das execuções bem-sucedidas registraram limpeza correta e estado do host sem alterações conforme
as verificações existentes do laboratório.

### Recursos observados e limites

| Ambiente | Duração, segundos | CPU supervisor, segundos | CPU filhos, segundos | RSS máximo de um filho, KiB |
| --- | ---: | ---: | ---: | ---: |
| Primeiro ambiente API/CLI | 54.678599351 | 0.124264 | 2.769029 | 18,100 |
| Ambiente API/CLI recriado | 6.951193177 | 0.049182 | 0.718900 | 17,100 |
| Ambiente combinado com navegador | 90.801095849 | 0.064060 | 2.245907 | 18,988 |

Uma amostra do renderizador de 3.00208119 segundos mediu 0.009948 segundos de
execução de tarefas, 4,654,556 bytes de heap JavaScript usado e 6,955,008 bytes
alocados. São medições limitadas: o RSS máximo de um filho não é a memória total
do appliance, e o heap não é o RSS do navegador nem um teste de capacidade.

A Alpha instalada não foi atualizada. Recriar o ambiente não equivale a reiniciar
o sistema operacional, testar perda de energia nem demonstrar continuidade do
plano de dados. IPv6, políticas grandes, carga prolongada e prontidão para produção
ficam fora desta evidência. CI final e revisão de publicação continuam sendo
requisitos separados. Consulte o [guia operacional](../src/firewall/docs/rules-pt.md).
