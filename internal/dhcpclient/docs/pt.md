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
## Perfil interno V4 de renovação antecipada

`Scope.EarlyRenewalV4` exige habilitação explícita pelo supervisor V4 e permanece
desligado por padrão. Desligado não cria worker, timer ou descritor exclusivos;
V3 rejeita a opção. Não ativa o runtime instalado nem oferece uma opção de API.

Com D conservador inalterado, autoridade restante R=D-t, instante do hook válido
g e concessão L: P=(L-28s)/2; I=min(g+P-t, R-22s), somente se I>=13s. O proprietário
aprovou esta fórmula provisória de Alpha em 2026-11-17. Constantes centralizadas
em early_policy_v4.go: adoção 12 s, resposta 5 s mais despacho 1 s, margem de token 3 s
e segurança 1 s. O timer absoluto BOOTTIME inclui suspensão. Nem g nem SIGUSR1
alteram lastGrant, epoch ou autoridade; somente um hook válido o faz. Uma única
solicitação pendente; hook espontâneo pode satisfazê-la sem atribuir o ACK ao sinal.

Após B2 não há solicitação de recuperação fechada: aguarda-se exclusivamente
um grant espontâneo com autoridade restante suficiente. Mínimo Alpha suportado:
71s com T1=floor(L/2) e custo de resposta medido abaixo de 1 s; a autoridade restante
real é sempre validada. 54 s é apenas o limite do calendário, não o mínimo de
continuidade/recuperação suportado. Abaixo de 71 s o encaminhamento permanece
fechado; a integração do aviso ao administrador continua pendente.

Despacho tardio, concessão curta, falha de relógio/sinal ou ausência de evidência
válida em 5 s revogam a evidência. O helper existente deve fechar e verificar o
encaminhamento (B2); o cliente não modifica esse estado do kernel. Observações
externas também rejeitam resposta vencida se o worker atrasar. Não há EXPIRE
fictício nem substituição automática da instância nesta implementação.

Aceitação integrada pendente: dez renovações consecutivas mantendo a mesma
conexão TCP e socket UDP. Cada limite superior de interrupção deve ser<=10s e
hook->Open<=12s; limites provisórios deste teste Alpha, não garantias do produto.
Medir fases, mínimo/mediana/máximo, perdas e CPU/memória/goroutines com/sem B1.

### Medição nativa do componente, 2026-11-17

Dois laboratórios Debian novos e isolados, mesmo ciclo de observação de 55 s
e concessão de 60 s. O processo medido inclui o componente cliente e o teste
Go; não representa os recursos totais do appliance ou da API.

| B1 | Janela (ns) | CPU processo (ns) | RSS amostrado máximo (bytes) | Goroutines mín/máx | Renovações reais |
| --- | ---: | ---: | ---: | ---: | ---: |
| Desligado | 55000796941 | 436522000 | 9007104 | 6 / 6 | 1 |
| Ligado | 55000182642 | 419576000 | 8978432 | 8 / 9 | 3 |

CPU por RUSAGE_SELF, RSS por `/proc/self/statm` e goroutines pelo runtime Go.
Uma comparação não demonstra melhoria de CPU/RSS. As duas unidades terminaram
corretamente; endereços, rotas, forwarding e namespaces do host coincidiram
com a base após a limpeza. Este teste não mediu sobrevivência de sockets
TCP/UDP nem a duração da interrupção.

Repetir com o teste fixo `scripts/dhcp-native-isolated.sh --early-renewal-off`
e `--early-renewal-on`, em Debian de laboratório descartável, com artefatos
root e unidade systemd limitada KillMode=control-group. O diretório de trabalho
deve conter `dhcp-native.test` deste pacote e `andeiva-dhcp-hook`.

## Revogação ao terminar o produtor

A saída do processo principal revoga imediatamente as evidências de concessão
e aquisição, antes de aguardar a drenagem de stderr. Um descendente que retenha
esse canal não prolonga a autoridade; eventos tardios e comandos não a recuperam.
A terminação do grupo e a coleta do processo são preservadas. Isso não garante
um prazo de encerramento se o leitor do fluxo ficar bloqueado.

## Interrupções medidas na Alpha — 2026-11-17

O proprietário aprovou provisoriamente o máximo de 10s por renovação apenas para
este teste do marco Alpha. Limite superior medido acima de 10s reprova o teste;
não é uma meta de produto. Três interrupções em Debian com duas vCPU mediram
7,897–9,406s,7,813–9,336s e 7,654–9,268s. A mesma conexão TCP entregou 308/308
mensagens com 15 retransmissões; o mesmo socket UDP enviou 1851 datagramas e recebeu
943 ecos:908 solicitações não observadas no destino após drenagem limitada. Há
perda UDP durante o fechamento. São observações da aplicação, não uma captura
exata de todos os pacotes. O ensaio completo FALHOU 141,15s na recuperação posterior
da API; não comprova aceitação completa nem autorização para ativar o perfil.

Concessão recomendada para operação desta Alpha: pelo menos 1h;120s apenas para
estresse em laboratório. Reduz a frequência de interrupções; não altera a
concessão do provedor nem permite rejeitar sua evidência válida.

A fórmula provisória aprovada inclui a reserva de adoção medida, sem ampliar
a autoridade nem relaxar os limites 10 s/12 s. Qualificação nativa e comparação final
de recursos continuam pendentes. Handover atômico é obrigatório antes de sair de
Alpha e não é projetado aqui. API e nova instância continuam tarefas separadas.
