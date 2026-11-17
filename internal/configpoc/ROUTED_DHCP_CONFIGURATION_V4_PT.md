# Configuração com DHCP ativo: contrato de leitura v4

Estado: contrato preparado para a fase a de ADR-074. Não inclui produtor,
exceção de admissão, API, fábrica ou ativação de rede. As restrições existentes
de publicação e admissão com DHCP ativo continuam vigentes.

O marcador obrigatório `configuration.routed-dhcp-configuration.v4` permanece
selecionado e exige os perfis routed, shared-reader, DHCP v3 e R2 existentes.
Leitores antigos devem recusá-lo mesmo sem a carga opcional. Sem o marcador,
continuam as regras v3 existentes.

O Work DHCP original, identidade de aquisição, concessão, epoch, revisão Running
original e escopo R2 físico não mudam. A geração original não é alterada para
aparentar igualdade com a configuração posterior. `preserve` exige igualdade
da revisão canônica **completa** de rede entre Work original, Before e Target.
Qualquer mudança de rede, incluindo LAN ou DNS, é `replace`; a leitura retorna
`ErrRecovery` até implementar o único contrato compartilhado de aquisição e
retirada de ADR-072/074. Não há outra fábrica ou identidade.

O cabeçalho contém no máximo duas referências imutáveis: `transition`,
selecionada antes de Intent/efeitos, e `continuation`, recibo final que conserva
a Transition, operação final e configuração final. Transition vincula
exatamente ator, namespace, operação, fingerprint, gerações, Before, Target,
Work DHCP, SourceSelection e Work agrupado quando aplicável. Não aponta para
seu futuro recibo ou operação final; não cria ciclo. A Continuation anterior
permanece enquanto houver uma Transition pendente.

SourceSelection já deve conter a operação accepted e sua admissão física R2.
Sua tupla completa deve coincidir com a aresta real do seletor anterior;
outro seletor autoconsistente apontando para o mesmo estado é recusado.
Somente seu Intent exato é permitido. O recibo mantém a operação final imutável
após retirada do namespace ou reutilização do catálogo circular. G1 visita
configurações, estado fonte, auditoria, Work agrupado e índices com seus limites
existentes. Não há outro histórico, compactador ou cache entre leituras.

A decodificação canônica recusa campos desconhecidos, aliases, duplicados,
null em alternativas opcionais e ramos misturados. Transition e recibo têm
limite de 16 KiB. Uma comparação de cabeçalho alterado materializa somente um
estado; o resumo histórico conserva dois hashes. As reservas não são duplicadas
e o crédito de fechamento não é compartilhado.

Stage/Save de metadados não pausam o encaminhamento. O futuro Commit com rede
idêntica pode fechar temporariamente o encaminhamento, mantendo a fonte sem
forçar DHCP. Ativação, acesso de gestão LAN/console, Confirm/rollback e medições
nativas são critérios pendentes de fases posteriores. Fixtures usam claims R2
reais de baixo nível e não demonstram admissão produtiva. Números de Docker não
representam recursos do appliance. Este contrato não encerra ADR-074 ou o marco
de routing.

Contrato completo: [English](ROUTED_DHCP_CONFIGURATION_V4.md).
