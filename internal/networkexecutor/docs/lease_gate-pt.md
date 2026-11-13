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

## Observação nativa do token do kernel

Após corrigir o protocolo numérico e a ordem das declarações do readback,
Debian 13 executou `TestNativeLeaseGateKernel` com sucesso (0,18 s). Um helper
com apenas NET_ADMIN instalou L3 WAN real, preparou e abriu o gate e terminou
sem fechar ou renovar o token. O harness root observou o token presente após
a saída e ausente 13 segundos depois, enquanto `enabled` permanecia presente.
Forwarding permaneceu zero; invariantes do host foram verificados fora dos
namespaces.

A autoridade era controlada pelo teste. Isso comprova expiração observável sem
o processo helper, não corte de pacotes, instante exato, SIGKILL/crash, suspensão,
DHCP real, trabalho durável selecionado ou recuperação produtiva. O namespace
isolado limpa a WAN retida. Exige jq além das dependências do harness. Executar
`ANDEIVA_LEASE_LAB_AUTHORIZED=1 ./lease-native-isolated.sh gate` apenas em grupo
systemd root limitado do laboratório autorizado, com PASS literal e nenhum SKIP.

## Qualificação de tráfego real preparada

O novo modo `gate-traffic` está preparado, ainda sem qualificação nativa.
Compilar sem privilégios com
`go test -c -o lease-native.test ./internal/networkexecutor` e verificar
`bash -n scripts/lease-native-isolated.sh`. Somente no diretório/cgroup do
laboratório Debian autorizado, executar
`ANDEIVA_LEASE_LAB_AUTHORIZED=1 ./lease-native-isolated.sh gate-traffic`.
Manter KillMode=control-group, LimitNOFILE=256 e limite externo de 45 segundos.
O modo adiciona timeout de 43 segundos e dois segundos para término forçado.

Cria três namespaces isolados, ligados somente por veth: gateway, LAN e WAN.
O helper NET_ADMIN existente instala L3 WAN, abre um gate breve e termina.
Somente após readback de política/gate o supervisor ativa encaminhamento IPv4
nesse namespace; IPv6 continua em zero. A cadeia posterior de qualificação mantém
aceitação established/related e aceita LAN→WAN apenas TCP18080/UDP18081 exatos.
Input/output permanecem DROP.

Servidor/cliente Go usam UID/GID62007, cinco conjuntos de capacidades vazios,
no_new_privs, pins host/gateway somente leitura e endereços benchmark fixos.
Trocam nonces novos de 32 bytes. O cliente conserva a mesma conexão TCP e socket
UDP. Root publica fase atômica, root e somente leitura, apenas após observar
live vazio com enabled presente. Depois, TCP estabelecido, UDP e TCP novo devem
terminar por timeout. EOF, reset, eco diferente ou servidor morto não comprovam
corte. Ambos os processos devem encerrar com PASS explícito.

O harness verifica estrutura do gate e política intactas (exceto contadores),
uso da aceitação established, estado de endereços LAN e IPv6 fechado. Desativa
encaminhamento IPv4 antes de limpar, termina/recolhe seus filhos; o namespace PID
limita a limpeza em falhas. O supervisor externo deve verificar invariantes
dual-stack/mount do host, limpeza do cgroup e CPU/memória pico. O novo modo não
tem PASS nativo ou medições comprovadas. Não prova autenticidade DHCP, trabalho
durável, recuperação, suspensão, instante exato do corte ou pacotes já enfileirados.
Não ativa interfaces host, topologia MACVLAN ou encaminhamento produtivo.
