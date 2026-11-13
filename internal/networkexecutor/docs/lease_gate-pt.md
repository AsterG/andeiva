# Gate isolado de autoridade DHCP

Biblioteca experimental que restringe encaminhamento WAN em namespace próprio,
diferente do host. Não está integrada à ativação ou recuperação do appliance.
Não altera interfaces, rotas, DNS, firewall ou energia do host. Qualificação
nativa de kernel/tráfego e medições de recursos continuam pendentes.

O supervisor confiável entrega descritores de namespaces, identidade do helper,
plano canônico WAN DHCP/LAN estática e proprietário autenticado da concessão.
O helper mantém somente NET_ADMIN, no_new_privs e grupos aprovados. O construtor
apenas lê e fixa recursos. Pode coexistir com LeaseExecutor; recusa outro gate
no mesmo processo/namespace.

`LeaseGateAuthority.Current` fornece concessão e digest do trabalho selecionado.
`Verify` deve verificar independentemente trabalho/reserva, delta L3, baseline
LAN intacta, política, identidade das interfaces e ausência de offload. O hash
sozinho não autoriza. Assembly deve serializar mudanças de autoridade/política.
Não há endpoint JSON novo nem execução de comandos arbitrários.

Sequência obrigatória:

1. `Initialize` cria fechada a tabela fixa `inet andeiva_lease_gate`, somente se
   ausente. Nunca adota nem substitui uma tabela existente.
2. `Close` remove abertura e token e verifica a tabela completa. Desativar e
   verificar encaminhamento IPv4/IPv6 do namespace.
3. Aplicar/verificar LeaseExecutor, política e trabalho selecionado.
4. `Stage` verifica encaminhamento desativado e autoridade atual; instala o token
   temporário enquanto permanece fechado. Consome a sequência antes da escrita.
   ACK perdido é resolvido por readback, nunca recriando o token.
5. `Open` verifica novamente e altera apenas o conjunto de abertura. Não recria
   o token, não amplia sua duração nem ativa encaminhamento IP.
6. Nova concessão exige Close e nova sequência. Revogação, falha, retirada e
   Confirm/rollback nunca restauram tokens anteriores.

A cadeia forward fixa usa prioridade -300 e DROP nas duas direções WAN, inclusive
conexões estabelecidas. Descarta IPv6 WAN. Não contém regras accept, exceções
conntrack, atualizações dinâmicas ou flowtables. A política accept da cadeia base
continua para o firewall obrigatório; não o substitui. Assembly deve excluir
offload e manter propriedade exclusiva de escrita.

O parser verifica tabela, conjuntos, ordem e expressões completos. Recusa objetos
extras, tokens permanentes, expiração ausente, overflow, chaves JSON duplicadas e
mudanças semânticas. CLOCK_BOOTTIME é lido depois da recepção: segundos restantes
mais um segundo de arredondamento devem terminar antes do deadline original.
Stage reserva dois segundos, mas o cálculo anterior não autoriza Open sem
verificar a duração real recebida.

`ErrLeaseGateUncertain` significa fechamento não demonstrado: o supervisor
independente deve desativar encaminhamento ou destruir seu namespace. Não afirmar
baseline restaurada nem permitir tráfego. A falha bloqueia a instância. Não há
adoção após reinício, journal novo ou recuperação de tokens. A recuperação por
trabalho selecionado/R2 permanece uma dependência separada.

O [contrato JSON](https://manpages.debian.org/trixie/libnftables1/libnftables-json.5.en.html)
usa segundos para timeout; Linux 6.12 [usa jiffies na expiração](https://github.com/torvalds/linux/blob/v6.12/include/net/netfilter/nf_tables.h).
Este corte exige execução contínua. Suspensão, pausa/restauração de VM e seu
comportamento temporal não são suportados nem demonstrados. Não altera energia.

Testes sem privilégios Linux/WSL:

```sh
go test -race ./internal/networkexecutor -run '^TestLeaseGate' -count=1
go vet ./internal/networkexecutor
go build ./internal/networkexecutor
go test -c -o lease-gate-native.test ./internal/networkexecutor
```

Os testes unitários usam doubles explícitos de kernel. Não comprovam sintaxe nft
nativa, filtragem de pacotes ou expiração após morte do helper. A futura prova
autorizada Debian deve reutilizar namespaces/helper isolados e verificar JSON e
unidades reais, ambas as direções/conexões estabelecidas, pausa/morte do helper,
ACK tardio, LAN intacta, invariantes dual-stack do host e limpeza. Não executar
testes privilegiados em WSL/CI compartilhado. Sem alterações de serviços
Docker/Helm, dependências ou DTO compartilhado do coordenador.
