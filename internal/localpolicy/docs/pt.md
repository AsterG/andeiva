# Serviços locais: compilador isolado

Esta POC de desenvolvimento valida declarações e gera JSON; não instala nada.
Na raiz do repositório, com a versão de Go fixada pelo projeto:

```sh
go test ./internal/localpolicy
go test -race ./internal/localpolicy
go vet ./internal/localpolicy
go test ./internal/localpolicy -run '^$' -bench BenchmarkCompile -benchmem
GOOS=windows GOARCH=amd64 go build ./internal/localpolicy
GOOS=darwin GOARCH=arm64 go build ./internal/localpolicy
```

O detector de corridas exige plataforma compatível e compilador C. Não são
necessários contêineres nem operações de rede privilegiadas. Fuzzing opcional:
`go test ./internal/localpolicy -fuzz FuzzDecode -fuzztime 10s`.

`DefaultManagement` recebe uma interface LAN de inventário confiável, endereço
local exato e prefixos de origem explícitos. Declara TCP 443 com autenticação
obrigatória; não inicia HTTPS. `Bindings` permite selecionar uma ou várias
interfaces LAN, WAN ou outras. Cada binding WAN exige `WANOptIn: true`. Zonas e
endereços devem corresponder ao inventário. IPv4 e IPv6 usam bindings separados
com origens da mesma família. Curingas e prefixos /0 são rejeitados.

`Canonical` valida e calcula a revisão de uma cópia independente. `Compile` gera
regras com proprietário e um lote JSON para criar uma tabela. `Preview` mostra
permissões adicionadas/removidas e indica confirmação obrigatória para mudanças
administrativas. `EffectiveView` filtra regras por serviço; editar o resultado não
altera declarações. `Reconcile` compara observações fornecidas e detecta listeners
ou regras ausentes e residuais. A correspondência não prova o estado real do kernel.

A tabela é `inet andeiva_local_poc`, hook input, prioridade 10 e política drop.
Não aplicar no host do appliance. Tráfego de controle ICMP/IPv6, loopback,
recuperação administrativa, autenticação real, inspeção de sockets e substituição
atômica não estão implementados. Drops de outras cadeias base continuam efetivos.
Nenhuma permissão de forwarding ou NAT é gerada. Não há comando de instalação.

Os testes cobrem declarações, conflitos, dependências, mudança de porta,
permissões ao desativar, várias interfaces, IPv4/IPv6, divergência de observações
fornecidas, serialização e compilação concorrente. Não demonstram tráfego real,
recuperação após falha, Commit Confirmed, auditoria nem transações persistentes.
O benchmark mede tempo e alocações do compilador, não memória do appliance nem
desempenho de pacotes.

Não há componente instalado para parar ou desinstalar. Atualizar ou remover este
pacote exige revisão normal do código. A integração depende da aprovação do
[desenho transacional compartilhado](../ADR.md), de um observador confiável e de
testes isolados em Debian. System → Local Services e Firewall → Effective Policies
são vistas Web/CLI/API planejadas, não implementadas aqui. VPN, DNS, DHCP, NTP,
portal, reverse proxy e WAF reservam apenas identidades de serviço.
