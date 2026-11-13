# Enlaces próprios do gateway

O supervisor root pode criar dois filhos MACVLAN em modo privado diretamente no
namespace gateway fixado e de propriedade exclusiva. Valida índice, nome, MAC e
MTU de cada pai pela leitura atual. Não move nem reconfigura os pais. As MACs dos
filhos derivam de uma identidade persistente local do nó. Os filhos permanecem desativados e sem
endereços: L3, forwarding e ativação pertencem ao executor transacional.

O gateway deve conter apenas loopback. Mudanças inesperadas do pai, enlaces
alheios ou confirmação incerta bloqueiam novas criações. A limpeza remove apenas
identidades observadas após a criação; nomes reutilizados não autorizam exclusão.
Restos incertos exigem destruir o namespace próprio do supervisor. Não adota
enlaces nem implementa recuperação entre processos. O supervisor mantém os
descritores até concluir a limpeza.

Testes sem privilégios cobrem ciclo de vida, cancelamento, enlaces alheios,
mudanças dos pais, substituições e confirmações incertas. O script opcional
`scripts/routed-links-native-isolated.sh` testa o mecanismo real com pais dummy
em namespaces privados de rede/montagem/PID. Exige Debian 13 descartável e grupo
systemd root limitado; nunca runner compartilhado. Não comprova NIC física,
DHCP, forwarding nem instalação do produto.
O produtor root também cria um pin gateway novo, sem adoção, em diretório vazio
root:root 0700. Montagens usam o FD retido do diretório. Unshare roda em thread
exclusiva fixada; falha de restauração retira essa thread. Operações fixas
nsenter/sysctl configuram apenas o namespace novo e verificam forwarding desligado
e IPv6 desabilitado antes de retornar. A limpeza registra detach e remoção
separadamente para repetir interrupções sem apagar uma substituição. O harness
nativo injeta ambas as interrupções e exige nova tentativa bem-sucedida e diretório
vazio. MNT_DETACH não comprova drenagem de processos: o supervisor deve parar seu
cgroup antes de liberar o namespace. Integração/ativação exige gates separados;
esses construtores não habilitam serviços instalados.