# Configuração do servidor DHCPv4

Estado: contrato e validação; não há servidor, listener, banco de concessões,
API administrativa ou integração de execução. O cliente DHCP WAN é separado.

O esquema 1 permite habilitação e até 32 escopos vinculados às interfaces LAN
do inventário confiável e à configuração de rede selecionada. Cada escopo declara
sub-rede, endereço do appliance, até 32 pools sem sobreposição, 256 exclusões e
256 reservas MAC. Reservas ficam fora da alocação geral, inclusive dentro de um
pool. Uma reserva excluída é rejeitada. A capacidade total declarada é limitada a
65.536 endereços antes das exclusões.

Opções: gateway, até quatro servidores DNS e quatro NTP, domínio ASCII canônico,
concessão entre 60 segundos e sete dias, renovação e revinculação ordenadas antes
do vencimento. Identificadores de cliente, relay, DHCPv6, opções arbitrárias,
DNS dinâmico e HA ainda não fazem parte deste contrato.

São rejeitadas interfaces ambíguas ou WAN, sub-redes/pools sobrepostos, endereços
de rede/broadcast e gateway dentro do pool sem exclusão. A decodificação tem
limites e rejeita campos desconhecidos, duplicados ou com aliases de maiúsculas.
Desabilitar mantém a configuração validada, mas a futura integração deve remover
todos os recursos exclusivos.

Antes da ativação: revisão do motor/licenças/dependências offline, transações com
confirmação/save/rollback, RBAC/auditoria e paridade Web/CLI/API; proteção Local-In
separada de forwarding/NAT; detecção de servidores conflitantes e testes reais de
concessões, reservas, esgotamento, reinícios e pressão de disco. Validação bem
sucedida não comprova essas capacidades nem autoriza tráfego.

Não se deve presumir que Debian minimal contenha servidor DHCP. O bundle offline
deve incluir o motor escolhido e todas as dependências compatíveis, procedência
verificada, checksums, SBOM e licenças. Não haverá download ou `apt` ao habilitar
a função. Kea é candidato; `kea-dhcp4-server` depende de `kea-common` na mesma
versão e outras bibliotecas. Este código ainda não instala esses componentes.

A instalação deve impedir que scripts do pacote iniciem um servidor concorrente
antes da habilitação explícita, preservando a política de serviços existente.
Não sobrescrever `policy-rc.d` nem desativar serviços alheios. Testar instalação
limpa/offline, dependências ausentes ou corrompidas, serviço preexistente,
atualização, interrupção, rollback e desinstalação sem remover pacotes alheios.

```sh
go test -race ./internal/dhcpserver
go vet ./internal/dhcpserver
go build ./internal/dhcpserver
```
