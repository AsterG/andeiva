# Experimento de configuração transacional

[English](en.md) · [Español](es.md) · [Projeto e critérios de aceitação](../README.md)

## Leituras verificadas do journal

A inicialização continua validando todos os registros confirmados. O armazenamento
mantém metadados leves, auditoria validada e o último estado durável. A auditoria
é copiada do validado ao abrir/gravar, como antes; não detecta imediatamente
alterações posteriores no disco. Configurações históricas leem registros limitados
e verificam identidade, permissões, proprietário, tamanho, sequência e hashes.
Arquivo alterado ou ausente retorna erro de armazenamento sem página parcial.
Recibos do estado v1 persistido não expiram nem são removidos do mapa. Replay mantém
Snapshot atual mais ReplayedGeneration original, autorização e vínculo ao conteúdo.

Não há migração, exclusão de histórico, checkpoint nem compactação.
Erros de integridade na consulta bloqueiam novas mutações, incluindo Confirm/Recover,
até reabertura íntegra; o estado indica recuperação necessária. Um prazo pendente
mantém rollback automático e os requisitos de persistência existentes. Apagar
registros ou redefinir o armazenamento não é recuperação. Permanecem
1.024 recibos, 2.048 registros por padrão, 64 MiB de journal e 1 MiB por registro.
Retomar o serviço ainda grava os registros de recuperação existentes. Isso prepara
leituras com menos memória; não resolve disco cheio nem comprova 5.000 ciclos
completos. Medições devem identificar dados, toolchain e se medem heap retido,
alocações ou RSS do processo. As verificações continuam abaixo.
Textos de auditoria legados não têm limite individual de bytes; as medições não
constituem um teto universal de heap.
A [comparação medida e reprodução](../READ_VALIDATION.md) distingue a redução de
memória do custo adicional de consultar revisões verificadas no disco.

Este guia se destina a um ambiente local de desenvolvimento confiável. O experimento
altera arquivos temporários de configuração e estados de componentes simulados.
Não configura firewall, proxy, interface de rede ou serviço ANDEIVA de produção.
Não exige privilégios root, Docker ou acesso de rede a um appliance.

## Executar as verificações

Use Linux com Go 1.27.4 já instalado e um compilador compatível com o detector de
corridas de Go. WSL é adequado para desenvolvimento; use seu sistema de arquivos
Linux nos testes de persistência, não um diretório montado do Windows. A ausência
de um requisito é um bloqueio; não enfraqueça testes nem instale ferramentas de
compilação no appliance para contorná-lo.

A partir da raiz do código-fonte:

```bash
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOTELEMETRY=off
go test -race -count=1 -v ./internal/configpoc
go build ./internal/configpoc
```

Registre o commit, a versão de Go, o ambiente, a saída completa e o código de
retorno. Uma compilação bem-sucedida só prova que o código compila. Testes ignorados
e cenários de falha não executados não são aprovações. Os armazenamentos temporários
pertencem ao harness; nunca os substitua por um diretório de dados do appliance.

Execute o cenário independente em um diretório privado novo no sistema de arquivos
Linux:

```bash
umask 077
poc_parent=$(mktemp -d /tmp/andeiva-config-poc.XXXXXX)
go run ./cmd/andeiva-config-poc -state-dir "$poc_parent/state" -iterations 20 > "$poc_parent/report.json"
cat "$poc_parent/report.json"
```

O comando aceita de 1 a 100 iterações e emite um relatório JSON com asserções do
cenário e observações de recursos. Exige um caminho absoluto novo para o estado e
um usuário Linux sem privilégios. Preserve o diretório e o relatório para inspeção.
Ele não remove armazenamentos existentes, instala serviços nem aplica regras de
motores reais.
Use um caminho canônico sem `.` ou `..`, separadores repetidos ou links simbólicos.
O diretório pai deve existir e permanecer sob controle confiável; caminhos
inválidos são rejeitados antes da criação de diretórios.

## Transições e autorização

`stage` cria Candidate. `validate` o verifica sem alterar Running. `commit` coordena
a aplicação nos componentes e só avança Running após sucesso. Com uma janela de
confirmação, a revisão permanece provisória até `confirm`; o vencimento aciona a
compensação. `save` copia explicitamente Running para Startup e não pode contornar
uma confirmação pendente. `recover` tenta reconciliar um estado efetivo não confiável.
`revoke` é estado protegido, independente do salvamento normal da configuração.

São operações tipadas do serviço exercitadas pelos testes, não comandos implementados
na CLI `andeiva` instalada. Os rótulos Web, CLI e API utilizam as mesmas permissões
do serviço. O harness fornece identidades confiáveis; não testa sessões de navegador,
autenticação HTTP, MFA ou identidade SSH reais.

Reabrir um processo e iniciar o sistema são casos distintos. A recuperação do
processo usa o estado transacional persistido; a inicialização explícita seleciona
Startup. Uma transação não confirmada é revertida de forma conservadora após o
reinício. Auditoria e revogações devem persistir sem exigir `save`.
O temporizador funciona dentro do controlador. Não há um watchdog independente
nem uma concessão temporária imposta pelo motor que prove o cumprimento do prazo
durante uma indisponibilidade do controlador.

## Falhas e recuperação

Preserve a saída e o comando exato de um teste com falha. Não remova bloqueios,
edite históricos, substitua hashes nem apague estados para obter aprovação. Se o
resultado de uma operação de armazenamento for incerto, interrompa as alterações
e reabra pelo caminho de recuperação previsto. Se um componente não puder reverter,
informe que requer recuperação; um estado parcial não é um commit bem-sucedido.
Um diretório novo serve para outro teste isolado, não substitui a recuperação do
caso original que falhou.

O armazenamento tem capacidade finita. Rejeitar operações no limite preserva o
histórico; não constitui uma política automática de retenção ou backup. Ao reabrir,
sob o bloqueio de escrita, são verificados todo o histórico confirmado, todas as
entradas e a correspondência entre `staging-v1.owner` e
`.andeiva-stage-v1/owner.json` antes de remover o único temporário órfão
`.andeiva-stage-v1/record.tmp`, limitado a 1 MiB. Os metadados identificam o formato
`andeiva.config.staging.v1` e um `store_id` compartilhado; a limpeza não depende do
sufixo de arquivos temporários de Go. Esta limpeza nunca remove auditoria confirmada.

Arquivos inesperados ou alheios, temporários antigos `.pending-*`, metadados
incompatíveis e inicialização parcial de propriedade bloqueiam a abertura e são
preservados. Esses casos não têm reparação automática. Preserve o diretório original
e a saída da falha para investigação; não apague nem edite marcadores, não renomeie
arquivos para introduzi-los no diretório de staging nem remova arquivos desconhecidos
para aprovar a recuperação. Um processo com o mesmo UID ou root está fora deste
limite de confiança.

Configuração e diagnósticos podem conter informações sensíveis. Mantenha evidências
privadas e compartilhe apenas o necessário para reproduzir o defeito, sem
credenciais nem dados alheios ao caso.

## Interpretação dos resultados

O esquema 3 adiciona declarações canônicas de serviços locais; os esquemas 1/2
preservam seus bytes e hashes exatos e não aceitam essas declarações. A migração
exige stage e commit, nunca reescrita automática do journal. Alterações nos serviços
locais e rollback histórico envolvendo o esquema 3 exigem prazo de confirmação
(30–120 segundos pela fronteira gerenciada). A expiração ou o reinício do serviço
durante uma operação pendente restaura o Running anterior; Save é rejeitado até a
confirmação. O rollback entre revisões legadas continua imediato. A inicialização
do SO carrega o Startup salvo. Esses contratos não demonstram listeners HTTPS/SSH
nem aplicação de políticas no kernel.

Escrita de arquivos, ciclo de processos, bloqueios e autorização comum podem ser
reais; a aplicação nos componentes permanece simulada. Registre essas categorias
separadamente. Meça CPU, memória residente, crescimento de disco e latência para a
carga executada. Um benchmark de configuração pequena não demonstra throughput
de pacotes nem certifica a capacidade do appliance.

Interromper processos, sincronizar arquivos e reiniciar não demonstra resistência
a uma queda física de energia. Este experimento não seleciona SQLite ou PostgreSQL,
implementa HA, assina históricos, cifra segredos, fornece autenticação de produção
nem valida coordenação real de nftables/proxy. Esses gates permanecem abertos.

## Reserva de capacidade: AND01 permanece parcial

Antes de aplicar um commit confirmado ou rollback histórico confirmado, o
coordenador exige espaço para seis registros: dois de ativação, até dois de
resolução e dois para uma recuperação/reabertura. Escritas comuns, revogações e
auditorias de solicitações rejeitadas não podem consumir os quatro registros
reservados enquanto houver confirmação pendente. O proprietário autorizado pode
confirmar usando essa reserva. Também são reservados recibos para a confirmação e
uma recuperação necessária; repetir Recover em estado saudável não contorna a
cota. O cálculo de bytes usa o máximo existente de 1 MiB por registro, cobrindo o
crescimento do estado e dos recibos sem aumentar limites.

O journal mantém limites de vida útil: 64 MiB, a quantidade configurada de
registros (2.048 por padrão) e 1.024 recibos. As escritas podem parar antes para
proteger a reserva. Uma auditoria sem capacidade retorna erro de armazenamento.
Estado, histórico e repetições exatas autenticadas continuam disponíveis na cota
se o serviço aberto estiver saudável. Journals já esgotados não são reparados:
uma retomada saudável com menos de dois registros disponíveis falha antes de
adicionar uma intenção ou aplicar uma revisão. Reaberturas repetidas e falhas
físicas de armazenamento continuam sujeitas a esses limites. Compactação,
retenção, ciclo de recibos e gestão de chaves exigem outro ADR revisado. Nenhum
registro é removido e o formato durável permanece inalterado.

Execute `go test -race ./internal/configpoc -run TestCapacity` e
`go test ./internal/configpoc -run '^$' -bench BenchmarkCapacityAdmission -benchmem`
no Linux. O benchmark mede somente admissão em memória, não RAM do appliance nem
throughput. O teste de bytes injeta contabilidade de cota e grava registros reais
de tamanho variável; não simula um disco fisicamente cheio. O benchmark de recursos
no Debian e a validação de falhas físicas permanecem pendentes.
