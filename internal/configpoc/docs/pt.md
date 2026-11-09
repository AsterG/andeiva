# Experimento de configuração transacional

[English](en.md) · [Español](es.md) · [Projeto e critérios de aceitação](../README.md)

Este guia se destina a um ambiente local de desenvolvimento confiável. O experimento
altera arquivos temporários de configuração e estados de componentes simulados.
Não configura firewall, proxy, interface de rede ou serviço ANDEIVA de produção.
Não exige privilégios root, Docker ou acesso de rede a um appliance.

## Executar as verificações

Use Linux com Go 1.27.3 já instalado e um compilador compatível com o detector de
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
histórico; não constitui uma política automática de retenção ou backup. Configuração
e diagnósticos podem conter informações sensíveis. Mantenha evidências privadas
e compartilhe apenas o necessário para reproduzir o defeito, sem credenciais nem
dados alheios ao caso.
Ao reabrir, temporários órfãos validados e limitados podem ser removidos após
verificar o histórico confirmado; registros de auditoria confirmados nunca são apagados.

## Interpretação dos resultados

Escrita de arquivos, ciclo de processos, bloqueios e autorização comum podem ser
reais; a aplicação nos componentes permanece simulada. Registre essas categorias
separadamente. Meça CPU, memória residente, crescimento de disco e latência para a
carga executada. Um benchmark de configuração pequena não demonstra throughput
de pacotes nem certifica a capacidade do appliance.

Interromper processos, sincronizar arquivos e reiniciar não demonstra resistência
a uma queda física de energia. Este experimento não seleciona SQLite ou PostgreSQL,
implementa HA, assina históricos, cifra segredos, fornece autenticação de produção
nem valida coordenação real de nftables/proxy. Esses gates permanecem abertos.
