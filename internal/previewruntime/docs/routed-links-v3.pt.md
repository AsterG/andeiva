# Enlaces próprios do gateway

O supervisor root pode criar dois filhos MACVLAN em modo privado diretamente no
namespace gateway fixado e de propriedade exclusiva. Valida índice, nome, MAC e
MTU de cada pai pela leitura atual. Não move nem reconfigura os pais. As MACs dos
filhos derivam da identidade da execução. Os filhos permanecem desativados e sem
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