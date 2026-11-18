# Qualificação do ciclo de vida do lançador DHCP LAN

Estado: fixture preparado; execução nativa e medições CPU/RAM pendentes. Não
ativa produto, transações selecionadas, WAN, forwarding ou NAT. Não repete nem
qualifica DORA/RENEW. Exercita lançador e papel selado reais, gateway isolado e
dois slots exatos; WAN permanece vazio.

A preparação exige Kea real com usuário dedicado, capabilities exatas, AppArmor
stock em enforcement, identidade pai/pidfd/start e socket AF_PACKET próprio no
ifindex LAN observado. Um handle de lançamento não comprova prontidão.

ADR-075 substitui o protocolo privado pela versão2. O pai confiável prepara
exatamente duas árvores de montagem separadas a partir dos descritores existentes
de configuração e concessões, antes de criar o namespace do filho. O filho
valida todos os slots com syscalls antes de criar arquivos com poller: FD3–9
mantêm suas funções, FD10/11 levam as árvores e FD12/13 os pins exatos de cgroups.
O bootstrap selado vincula identidades ordenadas e procedência do pai; peers
antigos ou malformados são rejeitados. Configuração permanece somente leitura;
concessões seguem leitura/escrita nos mesmos inodos. Ambas as montagens exigem
nosuid/nodev/noexec antes e depois da transferência. Não há fallback por caminhos,
cópia do armazenamento operacional para transferência, aumento de capabilities
ou ativação do dispatcher de produção. As cópias privadas limitadas já existentes
para validação com LFC continuam obrigatórias; a montagem que serve DHCP mantém
o diretório operacional original.
O reprodutor isolado do kernel passou; a qualificação do ciclo completo e seu
delta de recursos continuam pendentes.

O disable é verificado **antes de encerrar o supervisor**: Stop e drenagem,
pidfds mortos, folhas sem membros, zero sockets UDP/RAW/PACKET/UNIX, regras
fechadas preservadas e nenhuma configuração ativa mantida por processo ou pelo
observador. Somente a entrada gerada de runtime é removida. Concessões
operacionais ficam preservadas e não mudam na amostra desabilitada. Os dois
slots vazios mantêm os inodos até retirar a encarnação inteira; não há promessa
de custo kernel ou quantidade de cgroups zero.

As fases registram BOOTTIME, CPU, RSS/PSS por PID e memória do pai, que inclui
harness e infraestrutura compartilhada. Duas janelas de quatro segundos permitem
calcular deltas sem atribuir todo o pai ao Kea ou ativar controllers. Contador
obrigatório ausente reprova o teste: cada amostra CPU exige `usage_usec`,
`user_usec` e `system_usec`; campos adicionais são opcionais. Sem folha, as fases
antes/depois da infraestrutura mostram `own_cpu:null`, sem medição CPU da folha.
Esses números não são metas de sizing.

Executar os controles de desenvolvimento sem privilégios, com fonte read-only:

```sh
go test -race ./internal/previewruntime -run '^TestRoutedDHCPServer' -count=1
go vet ./internal/previewruntime
go test -c ./internal/previewruntime -o /tmp/kea-lifecycle-native.test
bash -n packaging/preview/tests/dhcp-server-launch-lifecycle-native.sh
```

O skip nativo padrão não é evidência. Chamadas padrão, CI ou não-root devem ser
recusadas antes de efeitos. Só root executa em Debian13 isolado autorizado, com
snapshot/console e unidade transitória exclusiva. Nunca Windows/WSL, appliance
de cliente ou junto com outra qualificação. Dependências já instaladas offline;
serviço stock masked/inactive e AppArmor intacto. Binário/script e ancestrais
devem estar protegidos por root.

O [procedimento completo](dhcp-server-launch-lifecycle-native.en.md) define a
unidade transitória, propriedades e placeholders explícitos de artefatos. Esse
bootstrap root de laboratório não comprova privilégios de produção.
O limite `LimitFSIZE=64M` da unidade serve somente à cópia de artefatos de até
64 MiB. Depois das cópias, chmod, diretório do fixture e hashes, o driver remove
`POSIXLY_CORRECT`, desativa o modo POSIX do Bash e executa
`ulimit -S -f 8192` e `ulimit -H -f 8192`. Nesse modo Bash usa blocos de 1024 bytes:
o resultado é 8.388.608 bytes. Antes de snapshots/unshare verifica os dois limites
e a unidade `bytes` em `/proc/self/limits`; filhos herdam o limite soft/hard
de 8 MiB, mesmo com `POSIXLY_CORRECT=1` no ambiente inicial. Nenhum limite do
produto muda.
Root captura InvocationID, resultado e contabilidade antes de parar somente essa invocação,
verificando FD store vazio e drenagem. Não reset-failed nem exclusão para ocultar
falhas.

A evidência permanece em `/var/backups/andeiva-kea-lifecycle.*`: JSON por fase,
observações, hashes e invariantes do host. Normalizam-se somente lifetimes de
endereços/rotas, metadados de versão nft e contadores de pacotes. Rede funcional,
forwarding e mounts do host devem coincidir. Falhas preservam evidência; a
unidade contenedora drena. Não instala pacotes, desabilita AppArmor, desmarca
serviços, modifica rede do host ou remove evidência.
