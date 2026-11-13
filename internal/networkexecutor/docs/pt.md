# Executor IPv4 estático em namespace — NET-EXECUTOR-001

`ObservedSnapshot` captura inventário IPv4 vazio real sem plano desejado ou PlanHash.
PrepareObserved recebe somente bindings físicos autenticados pelo supervisor; não
escreve endereços/rotas nem cria transações. VerifyObserved verifica baseline real.
RecoverObserved também exige identidade imutável original retida somente por
NewInOwnedNamespace; não concede propriedade L3. ObservedMatchesPrepared compara
todos os fatos físicos quando um plano desejado real for fornecido depois.
Igualdade não é autorização. O perfil inicial aceita dois enlaces próprios e
loopback opcional, sem endereços/rotas IPv4. Interfaces já configuradas e leases
DHCP continuam fora deste perfil.

Responsável: executor de rede. Estado: qualificação isolada verificada;
PR/integração pendentes. O laboratório isolado de routing utiliza o pacote; sem
ligação com API, CLI, runtime ou helper privilegiado do appliance.

`New(supervisorLifetime, trustedNamespaceFD)` duplica e fixa um descritor de
namespace de rede Linux. Verifica o tipo e rejeita os namespaces atual e de
PID 1. O supervisor privilegiado deve iniciar no namespace do host, controlar
todos os escritores do namespace descartável e manter o contexto de recuperação
até concluir `Restore`. Essa autoridade nunca vem de HTTP. Há um proprietário por
namespace dentro do processo; a exclusividade externa cabe ao supervisor.
Uma interrupção abrupta perde o plano de recuperação em memória.

`NewWithHost(supervisorLifetime, targetFD, trustedHostFD)` aceita o descritor do
host aberto pelo gestor de serviços antes de restringir privilégios. Duplica
ambos e verifica nsfs/tipo de rede, host igual ao namespace atual do supervisor
e destino diferente do host. Fechar os descritores do chamador não invalida os
próprios. A montagem confiável do serviço estabelece a origem do host; um inode
não a comprova. Nunca aceitar essa autoridade de HTTP, IPC não confiável ou
caminhos/descritores arbitrários. `New` mantém o controle de `/proc/1/ns/net` e
rejeita se inacessível; sem capacidades extras ou redução da proteção do host.

`Apply` exige revisão canônica `networkplan.Revision`, IPv4 estático, DNS `none`
e prefixos 1–30. Todos os enlaces devem estar sem endereços IPv4 e todas as
tabelas de rotas IPv4 vazias, incluindo loopback/local. Os enlaces já devem ter
o estado administrativo necessário. Migração de endereços existentes ou LAN de
administração, DHCP, DNS, estado dos enlaces, policy routing, IPv6, NAT, firewall,
sysctls, VPN e rede do host não são suportados. Não é um gestor de rede operacional
do appliance.

Executa somente `/usr/bin/nsenter` e `/usr/bin/ip` fixos: namespace herdado em FD 3,
ambiente fixo, executáveis/caminhos de root sem escrita não autorizada, prazo de
dois segundos e limite de 256 KiB por fluxo de saída. Sem shell, caminhos/comandos
arbitrários, instalação, listeners ou workers permanentes. O modelo assume root,
kernel e instalação confiáveis e propriedade exclusiva do namespace; outro processo
root hostil não é coberto.

Vincula observações confiáveis com `networkplan.Bind`. Une endereços IPv4 a
nome/índice/MAC de duas leituras iguais de
`ip -j link show`. O seletor IPv4 omite MAC e enlaces sem IPv4; resposta vazia de
endereços não significa inventário vazio de enlaces. Verifica identidade antes
de cada alteração e confirma semanticamente endereços e todas as rotas, incluindo
rotas conectadas/locais do kernel. Rejeita atributos desconhecidos de rotas e
endereços. Não comprova conectividade nem ativa encaminhamento ou inspeção.
Rejeita membros JSON duplicados com semântica exata de nomes JSON.
Nunca libera tráfego desconhecido para captura nem permite contornar inspeção.
`Verify` repete a leitura do plano ativo sem alterações: desvio ou leitura
indisponível bloqueiam permanentemente a instância.

Chamar `Restore` antes de `Close`. A compensação usa a vida do supervisor,
independente da solicitação, remove somente adições exatas tentadas e verifica o
snapshot controlado original. Mudança de identidade, falha de comando ou restauração
diferente bloqueiam permanentemente a instância. Verifica a identidade antes
de cada remoção; não é uma verificação
atômica contra escritores externos com CAP_NET_ADMIN, excluídos pela propriedade
exclusiva. Não criar outra instância para tentar admissão: preservar evidências
e destruir somente o fixture descartável próprio.
`Close` apenas fecha o descritor; não comprova restauração ou durabilidade.
Rollback do código: manter desconectado ou reverter o commit; sem alteração de
formatos persistentes, serviços ou configuração do host.

Testes sem privilégios ou alterações de rede, Go 1.27.4 em Linux/WSL:

```sh
go test -race ./internal/networkexecutor ./internal/networkplan ./internal/networkinventory
go vet ./internal/networkexecutor
go build ./internal/networkexecutor
GOOS=linux GOARCH=arm64 go build ./internal/networkexecutor
GOOS=windows GOARCH=amd64 go build ./internal/networkexecutor
GOOS=darwin GOARCH=arm64 go build ./internal/networkexecutor
```

Testes com comandos simulados e controles read-only de namespaces. Revisão
independente de root e arquitetura sobre `460fece`: sem achados críticos, altos
ou moderados. Repetição independente de race (`-count=3`): PASS em 1.647 s.

Qualificação Debian 13 amd64 de `460fece` (prefixo SHA-256 do binário `590a4005`):
PASS nos três namespaces para apply/readback/restauração tipados, TCP/UDP SNAT
com tuplas conntrack reais, ICMP relacionado, negação IPv6 e reversa não
solicitada, revogação TCP existente, routing sem NAT e NAT sem autorização de
encaminhamento. Limpeza e invariantes externos do host PASS. Helper limitado a
SYS_ADMIN/NET_ADMIN com FD 0 do host fornecido pelo supervisor; o supervisor root
carregou separadamente o módulo conntrack necessário.
Uma execução: 4.408428 s decorridos, CPU 1.116154 s, pico 32,321,536 bytes.
Não representa benchmark de capacidade ou desempenho do appliance.

Continuam sem suporte: migração da LAN administrativa existente, DHCP, ativação
runtime do appliance e recuperação durável após crash. Execução em contêiner e
orçamento de recursos do appliance não qualificados. Sem integração Docker/EKS/Helm
ou declaração de release ou conclusão do marco. Requisitos nos guias EN/ES/PT
do runner.
# Adaptador L3 DHCP isolado experimental

`NewLeaseInOwnedNamespace` é um executor separado e opcional. O construtor apenas
lê: exige LAN estática configurada, WAN DHCP vazia, regras IPv4 de roteamento
padrão e encaminhamento IPv4/IPv6 fechado. Reutiliza identidade e capacidades do
construtor não root para namespaces próprios; rejeita o namespace do host.
O contrato do executor estático existente permanece inalterado.

A composição confiável fornece `LeaseOptions.Current`: incarnation autenticada
do proprietário, identidade boot/run, PID/início, sequência crescente, hash da
configuração e vínculo de interface exatos, e prazo CLOCK_BOOTTIME. Não são
entradas JSON públicas. `Refresh` instala apenas endereço WAN e rota padrão
concedidos, verifica o estado real e preserva todos os fatos LAN. Renovação do
mesmo tuple atualiza somente evidência em memória. Um tuple novo retira primeiro
o lease anterior; compensação nunca restaura um lease já invalidado. Expiração
ou perda de autoridade retira WAN. Estado alheio ou falha de compensação bloqueia
o objeto. `Withdraw` restaura LAN/WAN vazia original; `wan_withdrawn` não significa
restauração de um lease anterior. `Close` recusa abandonar uma WAN instalada.

Este corte não possui worker de expiração, propriedade durável, recuperação entre
processos, NAT/DNS ou permissão de encaminhamento. A composição deve chamar
`Refresh` nos eventos/prazos. `Verify` apenas lê e não impõe expiração no kernel.
Uma nova instância rejeita WAN ocupada: endereços ou hashes não provam propriedade.
A recuperação futura exige trabalho selecionado autenticado do armazenamento de
configuração existente, não outro journal. Não adota managers/interfaces do host.

`go test -race ./internal/networkexecutor` cobre efeitos do construtor, fatos
inválidos/repetidos, drift LAN, leitura variável, mudança de lease, expiração,
cancelamento e falhas antes/depois de cada efeito com transporte simulado.
Qualificação nativa e medição de recursos deste adaptador estão pendentes;
evidência estática/DHCP anterior não qualifica esta integração.
