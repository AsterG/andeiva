# Fixture DHCP real para LeaseExecutor isolado

Qualificação experimental Debian 13. Resultado nativo e recursos desta integração
pendentes; testes anteriores qualificaram componentes separados. Não adiciona
API, formato persistente, outro banco, adoção do host ou topologia produtiva.

Compilar sem privilégios:

```sh
go test -race ./internal/networkexecutor -run DHCPLease -count=1
go vet ./internal/networkexecutor
go test -c -o dhcp-lease-native.test ./internal/networkexecutor
go build -o andeiva-dhcp-hook ./cmd/andeiva-dhcp-hook
bash -n scripts/dhcp-lease-native-isolated.sh
sha256sum dhcp-lease-native.test andeiva-dhcp-hook scripts/dhcp-lease-native-isolated.sh
```

Os dois testes nativos são ignorados fora do harness autorizado: PASS local não
é qualificação nativa. Transferir artefatos para diretório novo pertencente a root,
verificar hashes e arquivos regulares de um link, root, modo `0555`. Nesse
diretório, executar cada modo em uma unidade systemd separada:

```sh
ANDEIVA_DHCP_LEASE_LAB_AUTHORIZED=1 ./dhcp-lease-native-isolated.sh lifecycle
ANDEIVA_DHCP_LEASE_LAB_AUTHORIZED=1 ./dhcp-lease-native-isolated.sh owner-death
ANDEIVA_DHCP_LEASE_LAB_AUTHORIZED=1 ./dhcp-lease-native-isolated.sh manager-death
ANDEIVA_DHCP_LEASE_LAB_AUTHORIZED=1 ./dhcp-lease-native-isolated.sh broker-death
```

Exige `KillMode=control-group`, `RuntimeMaxSec=360s`, `TimeoutStopSec=10s` e
`LimitNOFILE=256`. A unidade externa começa nos namespaces normais do host;
o harness compara pins originais com `/proc/1` antes de montar em privado.
Somente laboratório Debian descartável autorizado, com `dhcpcd`, BusyBox
`udhcpd`, `ip`, `nft`, `unshare`, `mount`, `setpriv` e Bash. Não executar com
privilégios em WSL/CI/clientes. Não instala pacotes nem inicia daemons host.

Três namespaces contêm gestor, servidor DHCP e peer LAN. LAN inicial
`198.18.0.1/24`; WAN vazia. Cliente real root/privsep separado, somente aquisição;
helper UID/GID62006 somente NET_ADMIN e no_new_privs=1 com LeaseExecutor real.
Start/Wait permanecem em thread fixada para parent-death. Pipes anônimos root0600,
extremos herdados exclusivos, direção validada e close-on-exec autenticam a
composição. Bootstrap verifica PID/início do pai root, PID filho,
namespace/boot/run e incarnation DHCP. Frames canônicos privados limitados não
são entrada JSON pública nem contrato IPC produtivo.

A mudança de UID limpa Pdeathsig anterior ao exec. Cada papel rearma SIGKILL
após autenticar o pai, lê PR_GET_PDEATHSIG e verifica novamente PID/início e os
quatro UID root do mesmo pai. Mantém essa thread durante sua vida e só anuncia
readiness com o sinal verificado.

`Current` consulta o proprietário real durante cada operação. Preserva o prazo
CLOCK_BOOTTIME exato do cliente sem prolongá-lo ao ler. Grants usam Epoch/evento
real; sequência também avança na revogação. Rebind retira autoridade e L3 antes
de sinalizar o motor. Epoch revogado não volta a autorizar. Nenhum comando WAN
L3 manual substitui o executor.

Encaminhamento IPv4/IPv6 sempre zero e cadeia inet forward drop. Só permite DHCP
local WAN UDP68→67 ao servidor fixo/broadcast e UDP67→68 desse servidor;
o restante de input/output inet é descartado. Aquisição raw pertence ao papel
root/privsep. Não qualifica encaminhamento de tráfego.

`lifecycle`: BOUND, ACK RENEW sem novas escritas L3, rebind, reinício após retirada,
morte do servidor/expiração e rejeição de cache offline. `owner-death`: morte do
cliente root e retirada por perda de canal. `manager-death`: morte do helper com
WAN ativa, LAN intacta e reabertura rejeitada por WAN ocupada; WAN permanece até
destruir namespace. **Não é restauração nem recuperação entre processos**.
Trabalho selecionado autenticado durável e guard de expiração independente no
kernel continuam pendentes antes de permitir encaminhamento.

`broker-death` adiciona um pai relay root real. Após aplicar o lease real, mata
somente esse broker: o supervisor subreaper exige pidfd do helper legível e status
SIGKILL ao recolhê-lo. Saída normal por EOF não serve como evidência. Reabrir WAN
ocupada continua proibido; não afirma restauração. Morte do servidor também exige
pidfd legível, não apenas envio do sinal. Expiração preserva cada grant válido
posterior, inclusive ACK em trânsito; falha se perder autoridade antes do último
prazo observado. A negativa A→B rejeita indisponibilidade entre ambos os prazos.

Registrar PASS executado sem skips, hashes, CPU/memória do cgroup, invariantes
host dual-stack/links/endereços/rotas/regras/nftables/encaminhamento/mounts e ausência
de descendentes/namespaces após parar. Saída de PID1 privado e cgroup externo
limpam processos; não se sinaliza PID de servidor em cache. Excluir o nome do
namespace não prova o desaparecimento de todos os seus pins.

## Qualificação nativa registrada

No Debian 13 amd64, a fonte `97a26a2` executou os quatro modos com DHCP real e
leitura real de endereços/rotas do kernel. Lifecycle passou em 147,07 s;
owner-death em 9,69 s; manager-death em 7,58 s; broker-death em 10,13 s. Todos
preservaram endereços IPv4/IPv6, rotas, regras, nftables, forwarding e montagens
do host externo e limparam o ambiente isolado. CPU/pico em bytes por modo:
1,725861 s/49467392; 0,594272 s/36499456; 0,677219 s/37240832;
0,631642 s/45264896. São execuções individuais, não dimensionamento produtivo.

As primeiras tentativas nativas falharam no harness: faltava o contexto de vida
do observador e os pipes herdados bloqueantes não estavam registrados para os
prazos do Go. Foram corrigidos sem reduzir autenticação, prazos, privilégios ou
invariantes do host. O forwarding permanece fechado; este teste não comprova
expiração autônoma nem recuperação durável da WAN.