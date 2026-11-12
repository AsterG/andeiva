# Executor IPv4 estático em namespace — NET-EXECUTOR-001

Responsável: executor de rede. Estado: implementação para revisão, somente
qualificação isolada. Sem ligação com API, CLI, runtime ou helper privilegiado.

`New(supervisorLifetime, trustedNamespaceFD)` duplica e fixa um descritor de
namespace de rede Linux. Verifica o tipo e rejeita os namespaces atual e de
PID 1. O supervisor privilegiado deve iniciar no namespace do host, controlar
todos os escritores do namespace descartável e manter o contexto de recuperação
até concluir `Restore`. Essa autoridade nunca vem de HTTP. Há um proprietário por
namespace dentro do processo; a exclusividade externa cabe ao supervisor.
Uma interrupção abrupta perde o plano de recuperação em memória.

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

Vincula observações confiáveis com `networkplan.Bind`, verifica identidade antes
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

Comandos simulados e rejeições read-only de namespaces. Pendentes: execução real
privilegiada, Debian, revisão independente, execução em contêiner e medições de
CPU/RAM do appliance. Sem integração Docker/EKS/Helm ou declaração de release
ou conclusão do marco.
