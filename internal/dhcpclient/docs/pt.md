# Aquisição DHCP isolada

Perfil experimental do Debian 13, separado da API e do helper do firewall.
O supervisor executa dhcpcd com `--noconfigure`; receber uma concessão não autoriza
alterações de endereços, rotas, DNS ou permissões. Eventos inválidos, fechamento
do canal, morte do proprietário e expiração invalidam a evidência.
`RECONFIGURE` revoga sem conceder uma nova concessão. Renovar usa SIGUSR1 e
revincular usa SIGHUP; ambos exigem observações posteriores válidas.

## Reprodução

Compilar sem privilégios no Linux com o toolchain do repositório:

```sh
go test -race ./internal/dhcpclient
go vet ./internal/dhcpclient ./cmd/andeiva-dhcp-hook
go test -c -o dhcp-native.test ./internal/dhcpclient
go build -o andeiva-dhcp-hook ./cmd/andeiva-dhcp-hook
bash -n scripts/dhcp-native-isolated.sh
```

Transferir os dois binários e o script para um diretório novo pertencente ao root
no laboratório autorizado. Verificar os SHA-256 antes da execução; usar 0755 para
o diretório e os binários e 0700 para o script. Manter os nomes acima e definir
esse diretório como `WorkingDirectory` de uma unidade transitória systemd com
`Type=oneshot`, `KillMode=control-group`, `TimeoutStartSec=350`,
`TimeoutStopSec=10`, `TasksMax=64` e `MemoryMax=128M`. O comando da unidade é:

```sh
/usr/bin/env ANDEIVA_DHCP_LAB_AUTHORIZED=1 /bin/bash ./dhcp-native-isolated.sh
```

Registrar regras nftables, rotas e forwarding do host antes e depois. Consultar
o resultado e o journal da unidade e pará-la ao terminar. Repetir em outra unidade
com `ANDEIVA_DHCP_EARLY_SERVER_DEATH=1` para a negativa de servidor morto.
Nunca executar o teste privilegiado no WSL, CI compartilhado ou appliance de
cliente. O script verifica Debian 13, rejeita CI e valida os descritores dos
namespaces originais antes de montar caminhos privados.

## Resultados e limites

No Debian 13 com dhcpcd 10.1.0 e BusyBox passaram aquisição, exclusão de outro
proprietário, ACK real de renovação, revinculação, reinício, expiração e rejeição
da concessão armazenada sem servidor. O fixture aplica e remove explicitamente
somente seu endereço WAN isolado, preservando a LAN configurada. Duração 142,14 s,
CPU 0,445799 s e memória máxima 19.038.208 bytes. A negativa de servidor morto
passou em 35,02 s. A rede do host permaneceu igual. São medições de testes,
não capacidade do produto. A renovação sem aplicação L3 não passou no teste.

Isto não implementa adoção do ifupdown, rollback de interfaces principais,
renovação de NAT, continuidade administrativa ou perfil de privilégios de
produção. Uma falha é contida parando a unidade e seus descendentes; não remover
regras, rotas ou arquivos de terceiros para fazer o teste passar.
