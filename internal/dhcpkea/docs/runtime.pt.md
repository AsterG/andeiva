# Componente de servidor confinado

Experimental e desativado por padrão. Sem API, dispatcher de produção ou novo
banco de configuração. Reutiliza os controles do supervisor existente. Root deve
fornecer processo dedicado no gateway e namespace de montagem privado, FDs reais,
configuração compilada RO, diretório persistente de `_kea`, orçamento de
armazenamento e contexto limitado.

Tmpfs privados cobrem `/run`, `/var/lib` e `/etc/kea` antes de criar diretórios.
Configuração RO em `/etc/kea/kea-dhcp4.conf`; diretório persistente montado em
`/var/lib/kea`. Caminho fixo: `/var/lib/kea/kea-leases4.csv`. AppArmor permanece
intacto; revisões administrativas nunca restauram leases operacionais. O servidor
recebe somente NET_RAW/BIND_SERVICE; `kea-lfc` não recebe capacidades. Ambos usam
`_kea`, perfis originais e argumentos fixos.

Arquivos desconhecidos, links, ACLs, permissões/proprietários incorretos, PID de
LFC e excesso do orçamento são recusados. Root exclui outros escritores e mantém
mascarado o serviço original. Flock não substitui essa exclusividade nem uma quota
de disco. Todos os FDs herdados ficam CLOEXEC antes da execução.

Kea `-T` força `persist=false`: não valida histórico memfile. `kea-lfc -4 -d`
verifica cópias privadas de cada arquivo permitido; exige exit0, estatísticas
únicas de leitura/escrita sem erros, término e ausência de avisos, erros ou
truncamento. A saída nunca substitui originais. Hashes verificam alterações após
a inspeção; não são autenticação. Não há promessa contra corrupção semântica
arbitrária ou Root comprometido.

Cancelamento: SIGTERM, depois SIGKILL no orçamento existente de cinco segundos,
Wait e drenagem dos descendentes. O processo dedicado deve sair para liberar
montagens; Root verifica depois o cgroup completo. Os leases são preservados.

Entrada nativa: `go test -c -o server-native.test ./internal/previewruntime`, teste
`TestNativeRoutedDHCPServerV1`; variável `ANDEIVA_DHCP_SERVER_NATIVE_V1=serve|corrupt`.
Somente Debian13 isolado, nunca WSL/CI. FD3/4/5 fixam NET/MNT/PID do host; `/fixture`
privado root0700 contém `leases` de `_kea`0700. Cada execução usa montagens e proc
privados no cgroup agrupado fixo. LAN: `lan0`198.18.1.1/24, concessão única
198.18.1.100, duração120, T1/T2 60/105, subnetID17, sem DNS/NTP.

Root mantém clientes isolados até `prepared.json` com observação real de
processo/caps/NNP/AppArmor/namespace/socket RAW; isso não autoriza política.
Reutiliza o cliente dhcpcd revisado para BOUND/RENEW, interface não habilitada,
parada SIGTERM, reinício no mesmo diretório e recusa de linha corrompida mantendo
os bytes originais. Arquiva o marcador antes de reiniciar. Timeout120s sem
SIGTERM falha. Forwarding0 sozinho não bloqueia DHCP RAW; esse gate não é presumido.

Testes locais não comprovam DORA, persistência, transição LFC do AppArmor ou
desempenho de produção. Medições nativas e revisão independente pendentes.
Comandos locais e procedimento completo: [English](../runtime.md). Docker/EKS
e contratos compartilhados permanecem intactos.
