# Transações v2 preparadas de serviços locais

[English](TRANSACTIONS_V2.md) · [Español](TRANSACTIONS_V2_ES.md)

A integração conecta resolver/livro de evidências ao único coordenador v2.
Não ativa rotas HTTP/SSH, capacidades anunciadas, helpers instalados, listeners,
regras do host ou interfaces. Mantém esquemas firewall 4, local 3 e composto 5;
não cria outra base de configuração nem outro motor transacional.

`OpenServiceV2WithLocalPolicy` exige política da montagem confiável vinculada ao
mesmo Manager de autenticação. O construtor comum continua negando gravações
locais. `PreparedBridgeV2` fixa o receptor a partir do listener; corpos de requisição
não fornecem receptores ou scopes. Nenhum contrato público de transporte é adicionado.

A sessão é verificada antes do lock de configuração. Sob o mesmo lock são
verificados sujeito/login/revisão de credencial canônicos, operação admitida,
namespace, CAS global e projeção local. O resolver calcula alvo e prazos;
Rollback exige testemunho histórico composto verificado cujo firewall coincide
com o atual.

Stage/Validate não precisam de tokens e rejeitam evidência irrelevante. Commit
local exige confirmação de 30–120 segundos; aplicação imediata é negada. Rollback
usa 30 segundos fixos sem alterar DTO. Commit/Rollback/Save exigem prova de
recuperação. Confirm exige também uma prova por binding habilitado; se todos
estiverem desabilitados basta recuperação. Save é negado durante pending.

A reserva do conjunto completo é atômica, antes do intent durável e dos efeitos.
É liberada somente quando ausência de admissão é comprovada; publicação selecionada
ou incerta consome a reserva. Replay final reautentica sem tokens antigos ou
repetição de efeitos. Recuperação fica vinculada à sessão exata; endpoints permitem
outra sessão vigente do mesmo sujeito/revisão de credencial. TTLs de 20/60 segundos,
limitados pela janela/deadline. Tokens/handles não entram em configuração,
auditoria ou serialização comum.

Candidate/Running/Startup e gerações permanecem distintos por domínio; operações
locais preservam a candidata do firewall. Existe somente uma ativação/confirmação
global pendente. Ambos os domínios exigem readback antes de selecionar resultado.
Guards e rollback usam domínio e lease originais. Timeout/reinício usam intent
durável e readback autorizado, sem sessão ou tokens do usuário. O resultado
histórico da origem não é alterado.

Stage/Validate/Save nunca corrigem drift aplicando regras. Drift entre leituras
fica cercado sem Apply ou Running não verificado. A execução local admitida usa
contexto independente e limitado, preservando deadlines anteriores. Publicação de
provas ocorre após readback e seleção pending, com vista própria sem inventar
operação Confirm. O callback consulta somente registro de instâncias em memória:
sem auth, coordenador, disco, rede ou motores. Substituição invalida provas antigas.

O primeiro intent local adiciona a característica persistente obrigatória
`local_services_transactions.v1`, compatível com `boot_startup.v1`. A codificação
padrão antiga não muda. A qualificação privada compilou o leitor real de 9e59f35:
aceitou o store de controle sem Apply e rejeitou a característica local após 216
seleções antes de chamar motores. Não autoriza downgrade, cutover ou remoção do
histórico.

Reprodução Linux/WSL com Go 1.27.4 e dependências offline:

```sh
GOPROXY=off GOSUMDB=off go test -race -buildvcs=false ./internal/configpoc ./internal/localadmin -run 'TestCoordinatorLocalV2|TestLocalTransactionsV2' -count=3 -timeout=5m
go test -race ./internal/configpoc ./internal/localadmin -count=1 -timeout=12m
go vet ./internal/configpoc ./internal/localadmin
go build ./cmd/... ./internal/...
```

Testes de integração usam journal, autenticação, livro e guardian reais com
motores simulados. Testes de falha do coordenador simulam explicitamente a
autoridade de evidências e persistem hashes simulados entre saídas reais do
processo. Não demonstram regras do kernel ou listeners reais.

Permanecem separados helper/listeners reais e handoff HTTP/SSH
e cutover Web/CLI/API. Boot do SO com Local Running diferente de Startup ainda
falha antes de efeitos; ativação segura é próximo trabalho obrigatório. Não fecha
reservas físicas/GC, exportação protegida, AND-01/02 ou resiliência global. Antes
da ativação, rollback remove código preparado sem uso; store selecionado exige
leitores compatíveis, nunca escritores v1 em paralelo.

A qualificação nativa no Debian 13 executou os binários exatos como UID 1000,
com no-new-privileges e rede isolada: tempo combinado 3,916337 s, CPU 1,764321 s
e pico de memória cgroup de 23.621.632 bytes. Inclui journals e provas de
autenticação/evidência reais com motores simulados. Não demonstra ativação de
helper/listeners reais, desempenho de tráfego ou recursos de todo o appliance.
