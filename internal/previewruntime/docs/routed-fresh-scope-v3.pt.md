# Âmbito novo após parada normal do serviço

Integração experimental do armazenamento selecionado distingue boot do sistema
e instância do serviço. O mesmo BootID pode usar outro RunID e namespace gateway
somente com recibo root autenticado e readback real de IPv4/tabelas vazias.
As regras de propriedade dos snapshots estáticos permanecem iguais.

Root pré-aloca um arquivo regular de 4096 bytes, proprietário/grupo 0:0, modo
0600, um link, sem ACL. Depois de esperar os filhos e fechar o namespace anterior,
grava `RootRetirementReceiptV3` no mesmo arquivo e executa fsync. O codec contém
âmbito anterior, digest de metadata, instante BOOTTIME original da drenagem e
digest do JSON canônico sem seu campo de integridade; espaços completam o slot.
O digest detecta gravações incompletas; a origem root do FD autentica o emissor.

Root vincula o digest dos 4096 bytes à nova identidade e entrega ao helper apenas
FD O_RDONLY e `RoutedFreshScopeBindingV3`. O helper duplica e revalida o FD, lê o
trabalho selecionado, reutiliza `PrepareBoot`/`Observe`, exige ausência de todas
as tabelas (incluindo gate de lease) e observa forwarding IPv4/IPv6 fechado.
Root deve atrasar sockets do motor DHCP até boot LAN; a verificação real de
ausência de listeners não é ignorada.

A montagem chama `PrepareServiceRestartViewV3` com a identidade anterior do
recibo verificado. Sua metadata Target/Saved selecionada configura o motor;
Saved não deve ser substituído por Startup. O `prepare_boot` privado relê trabalho
e recibo e compara destino/baseline antes da preparação somente leitura. Metadata
sozinha nunca autoriza efeitos.

A API negocia `routed_fresh_scope.v3` com integridade e inventário; DHCP é
independente. `fresh_scope` recebe apenas referência de trabalho selecionado.
Pedidos não aceitam recibo, identidade, deadline ou flag de prova. O mesmo
armazenamento registra `configuration.routed-fresh-scope.v3` persistente. DHCP
termina como `scope_retired`, não `withdrawn` nem `restored`; mantém trabalho e
deadline original. Preserva outcomes e deadlines de confirmação pendentes.
Reiniciar o serviço mantém Running, LastGood e Startup selecionados, mesmo quando
Running difere de Startup. Um commit pendente volta ao Previous exato; nunca é
confirmado implicitamente. O registro tipado vincula origem e recibo; o helper
deriva o mesmo destino pela leitura completa antes dos efeitos. Reiniciar o OS
continua selecionando Startup e não é habilitado por este perfil de mesmo BootID.
Histórico selecionado e recibo
retido pelo helper devem coincidir; endereço IP ou token anterior não bastam.

Testes focais usam arquivos/pools reais e doubles explícitos de autoridade física.
Cobrem reinício completo/pendente com mesmo BootID, deadlines intactos,
continuação do audit exato de retirada, rejeição de prova enviada pelo caller e
FD inválido. Qualificação nativa root drain/recibo/FD/namespace/helper e recursos
permanecem pendentes. Morte de root sem recibo completo bloqueia recuperação;
limpeza ExecStopPost/crash continua como gate separado pendente. Suspensão,
pausa de VM e snapshots não são suportados. Não há alegação de ativação do host.
Paradas repetidas durante recuperação boot-boundary ainda pendente podem reter
ambos os slots System; outro boundary permanece bloqueado até existir retirada
comprovada separadamente. Este incremento não descarta essas reservas.

O modo explícito `routed-launch-native.sh --isolated-fresh-scope-lab TEST_BINARY`
verifica FD14 somente leitura no helper, ausência de herança e acesso pela API
sem capacidades, e rejeição de recibo antigo deliberadamente sem correlação com
o histórico. Não comprova recuperação nem reinício da API com esse recibo. O modo
separado `--isolated-integrity-lab` verifica inicialização agrupada e reinício da
API mantendo o helper, sem recibo de retirada. Nenhum substitui a recuperação
instalada same-Boot ou o teste de reinicialização do sistema.

```sh
go test -race ./internal/configpoc ./internal/previewruntime ./internal/firewallipc -run 'Test(RoutedFreshScopeV3|RootRetirementReceiptV3|RoutedOSBootBoundary|ColdContinuationV1)' -count=1
go vet ./internal/configpoc ./internal/previewruntime ./internal/firewallipc
```
