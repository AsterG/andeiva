# Qualificação nativa isolada do LeaseExecutor

Teste opcional para laboratório Debian 13 autorizado e descartável; não ativa
o appliance. Não altera interfaces, IP, rotas, DNS ou encaminhamento do host.
Exige serviço systemd limitado com `KillMode=control-group`,
`RuntimeMaxSec=120s`, `TimeoutStopSec=10s` e `LimitNOFILE=256`. Nunca executar rede
privilegiada em WSL, CI ou appliances de clientes. Execução nativa, revisão
independente e medição de recursos deste fixture estão pendentes.

Compilar sem privilégios:

```sh
go test -c -o lease-native.test ./internal/networkexecutor
bash -n scripts/lease-native-isolated.sh
sha256sum lease-native.test scripts/lease-native-isolated.sh
```

Transferir os arquivos para diretório novo pertencente a root; verificar hashes
e usar arquivos regulares de um link, pertencentes a root e modo `0555`.
O supervisor precisa de `ip`, `nft`, `unshare`, `mount`, `setpriv`, `cmp` e Bash
padrão Debian. Não inicia daemon nem servidor DHCP. Dentro do serviço, usar esse
diretório de trabalho e executar:

```sh
ANDEIVA_LEASE_LAB_AUTHORIZED=1 ./lease-native-isolated.sh
```

O harness valida descritores originais e namespaces privados mount/net/pid antes
de montar. Rejeita entrada direta sem descritores ou com namespace atual igual
ao host. Um `/run` privado contém binário e namespace peer. Dois pares veth sem
conexão com interfaces host formam LAN/WAN: LAN `198.18.0.1/24`, WAN vazia.
Encaminhamento IPv4/IPv6 zero e três cadeias inet com política drop.

Um processo UID/GID 62006 sem capacidades deve rejeitar o construtor sem efeitos.
Outro, com somente NET_ADMIN nos cinco conjuntos e no_new_privs=1, usa construtor
e leituras reais do kernel: concessão, replay, renovação do mesmo tuple, mudança
de endereço, revogação, expiração CLOCK_BOOTTIME e retirada. Um terceiro processo
deve rejeitar WAN ocupada enquanto o proprietário original mantém seu estado.
A negativa final revoga autoridade após a última leitura real; não substitui
bytes do transporte. A compensação deve restaurar LAN/WAN vazia exatas. Verifica
descritores somente leitura, identidade, encaminhamento fechado e firewall
inalterado.

Os fatos do lease vêm de callback do teste: qualifica realização L3, não protocolo
DHCP, IPC autenticado, propriedade persistente, expiração autônoma,
encaminhamento ou administração acessível. A evidência DHCP anterior é separada.
Registrar hashes, resultado completo, CPU/memória máxima do cgroup e ausência de
descendentes/namespaces após parar. O supervisor externo deve comparar links,
endereços, rotas, regras, nftables e encaminhamento do host antes/depois, também
em falha ou parada forçada. Um PASS não comprova sozinho esses invariantes nem
limpeza completa. Não relaxar controles para fazer o teste passar.
