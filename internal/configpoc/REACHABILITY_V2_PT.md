# Inspeção de referências v2 somente para leitura

[English](REACHABILITY_V2.md) · [Español](REACHABILITY_V2_ES.md)

Este inspetor interno verifica o conjunto conhecido de referências alcançáveis
a partir de uma seleção v2, dentro de limites explícitos de trabalho. Não está
conectado a um runtime, API pública ou CLI. Não abre um coordenador, aplica
políticas, recupera transações, remove arquivos nem gera candidatos à recuperação
de espaço.

## Acesso e resultado

`inspectReachabilityV2` recebe um `os.Root` já aberto, um contexto e um
`v2ReachabilityBudget`. No Linux, abre o `checkpoint.lock` existente somente para
leitura e adquire um bloqueio exclusivo não bloqueante. Um bloqueio ausente ou
ocupado causa erro; o inspetor nunca o cria. São verificados identidade,
proprietário, permissões, tipo e sistema de arquivos da raiz e dos arquivos.
O diretório permanece privado; a inspeção não amplia permissões. Outras
plataformas rejeitam esta inspeção do armazenamento.

O inspetor enumera entradas em lotes limitados e valida o par selecionado e os
segmentos limitados de seleções exigidos. Percorre referências tipadas de estado,
índices de operações, migração, configuração, auditoria, recuperação e evidências
de revisão verificada. As leituras validam hashes e estruturas JSON estritas.
Antes de retornar sucesso, verifica novamente o seletor e a identidade retida
do diretório e do bloqueio. Não chama `openV2` nem executa suas rotas de
recuperação e limpeza.

`Complete=true` significa que o conjunto conhecido de referências foi verificado
dentro dos limites e que a seleção observada permaneceu consistente. **Não**
comprova elegibilidade para remoção, confirmação de exportação, marca durável de
GC ou espaço reservado para recuperação. Arquivos sem referências não podem ser
considerados lixo com base neste relatório. Conteúdos opacos de auditoria
continuam sendo folhas protegidas e opacas.

Cancelamento, limites esgotados, referências ausentes, conteúdo malformado,
estruturas não suportadas ou identidades inconsistentes retornam erro e
`Complete=false`. Contadores parciais indicam progresso, não uma marca de
segurança utilizável. Uma gravação posterior torna o relatório uma observação
histórica; ele não fornece bloqueio ou autorização a um futuro coletor.

## Semântica das referências

Cada hash tem o significado definido no contrato de seu campo. Uma identidade
semântica de revisão não é automaticamente o nome de um arquivo que contém um
invólucro `Revision`. Configurações embutidas são validadas no objeto que as
contém. Conteúdos canônicos externos são seguidos apenas pelos contratos tipados
existentes de gravação e leitura. Chaves do índice de recuperação não são
referências a objetos.

O percurso preserva o contexto de cada aresta: nível e prefixo do índice, estado
selecionado, finalidade da evidência e relações de identidade. Reutilizar um
hash ou nó visitado não permite ignorar a validação em outro contexto. Um
contexto não resolvido ou incompatível impede um relatório completo.

## Limites de recursos

O chamador fornece limites para entradas, objetos únicos, arestas, chamadas de
E/S, bytes lidos, bytes de conteúdo ativo e profundidade. O inspetor rejeita
limites inválidos e interrompe o trabalho quando um limite admitido é excedido.
O acompanhamento de objetos e arestas permanece em memória, limitado por esses
valores.

`PeakActiveBytes` mede bytes de conteúdo contabilizados; não representa o heap
total do Go, RSS, cache do sistema de arquivos ou reserva física. A liberação
necessária de descritores continua mesmo após a interrupção do trabalho. O
cancelamento é cooperativo entre operações de arquivos: não interrompe uma
leitura bloqueada no kernel nem garante um prazo máximo de relógio.

Esta implementação não qualifica um histórico de 674.000 inodes. O percurso de
grandes armazenamentos exige trabalho separado com memória externa e medições.
Benchmarks de CPU, RAM, E/S e latência do appliance continuam pendentes.

## Reprodução e limites das evidências

Na raiz do repositório, em Linux/WSL, com Go 1.27.4 e dependências já disponíveis
localmente:

```sh
GOPROXY=off GOSUMDB=off go test -race -mod=readonly -buildvcs=false ./internal/configpoc -run '^TestV2Reachability' -count=1 -timeout=5m
go vet -mod=readonly -buildvcs=false ./internal/configpoc
go build -mod=readonly -buildvcs=false ./internal/configpoc
```

Os testes focais usam armazenamentos temporários reais e motores simulados.
Cobrem conteúdo do journal e contadores de chamadas ao motor sem alterações;
estados preparados e Candidate; referências de commit, confirmação e boot;
bloqueios ausentes, ocupados ou substituídos; limites e cancelamento; arquivos
estranhos ou malformados; contabilização de leituras de migração; contexto de
arestas e auditoria opaca. Não exigem privilégios nem um appliance ativo.

Esses testes não demonstram continuidade real do tráfego, reinicialização do
sistema, perda de energia, cotas ou reservas físicas, recuperação segura de
espaço ou desempenho de produção. Não habilitam exportação, confirmação ou
remoção de dados protegidos. AND-01/02 e a ativação do runtime continuam sendo
etapas de qualificação separadas e abertas.

A qualificação nativa Debian 13 AMD64 como UID 1000 sem capacidades passou na seleção completa TestV2Reachability: 0,449149 s, CPU 0,229975 s e pico de memória cgroup de 13.561.856 B. Os testes preparam estados com journals temporários reais e motores simulados; a inspeção não chama os motores. Nenhuma política do kernel, listener ou estado do appliance foi alterado. O cgroup inclui custos de teste/cache; não representa RSS de serviço nem garante capacidade. Race completo de configpoc, vet/build, compilação cruzada, SAST e verificação de segredos aprovados; revisão independente sem C/H/M pendentes. Esta evidência não qualifica GC, reservas ou AND-01/02.
