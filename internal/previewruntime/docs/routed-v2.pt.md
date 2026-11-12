# Autoridade de configuração roteada

O supervisor pode fornecer ao controle V2 uma autoridade roteada exclusiva. A
entrada administrativa não seleciona namespaces, pools, caminhos de artefatos,
identidades do helper ou capacidades de ativação. Firewall 6 e serviços locais
3 formam uma candidata 7 e uma transação protegida conjunta.

Antes de armar, o coordenador seleciona objetos tipados de propriedade,
dependências e identidade com o Intent e as reservas existentes. O helper
verifica esse plano e seu prazo original, aplica lotes compilados e lê o estado
efetivo. Confirm utiliza a operação original e a revisão de Pending; Save copia
Running confirmado completo para Startup.

Fechar API/catálogo preserva helper e tráfego. Reabrir o controlador preserva o
estado confirmado; commits pendentes seguem a compensação de reinício
existente. Outro helper ou boot não pode adotar identidade anterior nem criar
um prazo novo.

`TestRoutedPhysicalCoordinatorConfirmedLifecycle` usa armazenamento,
autenticação, reservas físicas, compiladores e guardian reais com transporte
kernel/rede simulado. Também substitui o helper na mesma instância autenticada
de namespace: preserva o estado confirmado e reconcilia a parada ordenada de um
helper pendente por Intent de recuperação. Outra identidade de execução é
recusada antes dos efeitos. Não comprova tráfego real, falta de energia ou boot.
Boot agrupado e IPC produtivo continuam bloqueados até validar a
integração. O router V2 recusa mutações V1; o despacho de tentativas V1 migradas
conhecidas ainda requer integração. Consumo de recursos pendente de medição;
estas provas não demonstram capacidade do appliance.

Teste Linux: `go test -race ./internal/configpoc ./internal/previewruntime
./internal/localnft ./internal/routedactivation`.

O teste Startup6 cria outra instância autenticada de namespace com as três
tabelas administradas ausentes. Uma preparação somente leitura captura esse
estado real; Intent e reserva de sistema são selecionados antes dos efeitos.
O prazo é exatamente Started original mais dez segundos. Só a leitura
confirmada publica a nova propriedade ativa. Duas regras schema4 importadas e
sua revisão salva são preservadas. A base prospectiva separada só é aplicada por
Rollback explícito posterior; não é apresentada como ruleset anterior real.
A candidata é preservada sem rebase silencioso se Startup mudar Running.

O transporte kernel/rede é simulado. Startup4 inicial sem plano L3 continua
recusado até integrar o perfil explícito sem rede; nenhum plano padrão é
inventado para contornar essa limitação.

O perfil de artefatos sem rede distingue os enlaces observados de um plano de
rede desejado. A candidata schema4, habilitada por capacidade, captura ambos os
domínios; o proprietário do grupo rejeita escritas independentes de firewall e
serviços locais. A validação da inicialização exige o testemunho protegido da
revisão salva, uma observação exata e a política legada prospectiva identificada
separadamente. Não implementa o adaptador físico sem rede nem ativa uma opção
do instalador.
