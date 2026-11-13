# Runtime DHCP selecionado V3

Integração experimental para um namespace de rede próprio diferente do host.
Os perfis estáticos mantêm o protocolo e a semântica dos snapshots existentes.
Não implementa adoção de interfaces do host, servidor DHCP, NAT, DNS ou
forwarding seguro durante suspensão.

A montagem root fornece `RoutedHelperOptionsV3.DHCP`: adapter LAN selecionado,
descritores target/host fixados, rede canônica, proprietário fixo e callback
`Current`. Este deve autenticar o canal herdado de escritor único do proprietário
DHCP separado, PID/start/incarnation, sequência e deadline BOOTTIME absoluto
original. A API não pode fornecer esses fatos. A API habilita `RoutedDHCP` e
recebe `runtime.DHCP`; a montagem confiável chama `Reconcile(ctx)` nos eventos
do proprietário e `Withdraw(ctx)` antes de alterações incompatíveis. Este
incremento não conecta o produtor automaticamente nem expõe endpoint HTTP de
leases.

O canal privado negocia `routed_dhcp_selected.v3` após integridade e inventário.
Begin/current e retire recebem objetos vazios. Apply/open/withdraw/live recebem
somente o hash do trabalho selecionado; verify recebe hash do snapshot e estado.
O helper verifica independentemente o grafo G1/R2 completo antes de efeitos.
Um hash localiza trabalho; não comprova propriedade.

Sequência: fechar gate e forwarding, capturar grant autenticado, selecionar
trabalho preparado no armazenamento existente, aplicar WAN, verificar estado
real, selecionar aplicado, preparar e ler token kernel limitado, abrir sem
recriá-lo e habilitar forwarding verificando gate/política. A renovação atual
retira e arquiva a WAN anterior antes do próximo grant, causando interrupção
mesmo com endereço igual. Autoridade inalterada apenas verifica o token atual;
não estende seu deadline.

Perda do proprietário ou bloqueio persistente de integridade fecha e retira
através do helper retido. A expiração kernel não depende da sobrevivência da
API/helper. A recuperação selecionada precede o boot LAN, retira somente o delta
WAN autenticado, arquiva e libera o adapter LAN. Somente um terminal selecionado
exato de retirada permite reconstruir gate fechado; nunca um token ativo.
Outro namespace exige prova de âmbito novo; reinício normal do serviço com
o mesmo BootID e retirada do âmbito continuam pendentes de integração. Prova
insuficiente bloqueia a recuperação.

Testes focais com race cobrem negociação, rejeição de autoridade em pedidos,
histórico real do armazenamento, ordem dos efeitos, perda do proprietário,
retirada, replay, recuperação de gate fechado e rejeição de forwarding alheio.
Os testes unitários de runtime usam doubles explícitos de kernel/proprietário;
não comprovam forwarding nativo. Reprodução:

```sh
go test -race ./internal/networkexecutor ./internal/firewallipc ./internal/configpoc ./internal/previewruntime -run 'Test(RoutedDHCP|LeaseSelectedV3Archived|LeaseForwardingV3|RoutedCodecV3|RoutedSessionV3)' -count=1
go vet ./internal/networkexecutor ./internal/firewallipc ./internal/configpoc ./internal/previewruntime
```

Pendentes: qualificação nativa produtor/runtime selecionado, exceções de controle
local DHCP sob política real, readback do perfil forwarding/sysctl, recuperação
de âmbito novo com mesmo BootID, recursos e revisão independente. Testes isolados
anteriores de lease/gate não comprovam essas combinações. Apenas execução
contínua: suspensão, pausa/snapshot de VM e retirada de pacotes já enfileirados
não são garantidos. Não se afirma prontidão de produção nem ativação do host.
