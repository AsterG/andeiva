# Inventário de interfaces somente leitura

`networkinventory.Discover(ctx)` observa interfaces, endereços IPv4/IPv6 e flags do
sistema sem modificar endereços, rotas, zonas ou forwarding. Não inicia processos
nem listeners. Os tipos Go são internos; ainda não são um contrato administrativo
Web/CLI/API.

Os bits do endereço do host são preservados; um endereço sem máscara tem
`Prefix == nil`. `AdminUp` e `Running` não comprovam portadora física, velocidade ou
conectividade. Gateway, DNS e origem DHCP/estática não são inferidos.

No Linux, `device-backed` indica um link de dispositivo e pode ser uma NIC virtual
apresentada pelo hipervisor. `virtual` identifica o caminho virtual do kernel.
Metadados ausentes ou inseguros permanecem `unknown`; loopback é identificado por
seu flag. Outras plataformas mantêm `unknown`, exceto loopback.

Duas observações completas são comparadas; mudanças observáveis retornam erro sem
dados parciais. Não é um snapshot atômico do kernel. O cancelamento é verificado
entre chamadas e não interrompe uma enumeração padrão já iniciada.

Limites do resultado: 256 interfaces, 256 endereços por interface, nomes de 256
bytes e endereços de hardware de 64 bytes. A enumeração inicial do sistema pode
alocar memória antes desses limites. Códigos estáveis:
`network_inventory_unavailable`, `network_inventory_limit`,
`network_inventory_invalid_observation`, `network_inventory_changed`.

Testes a partir da raiz do repositório:

```sh
go test -race ./internal/networkinventory
go vet ./internal/networkinventory
go test -run '^$' -bench Discover -benchmem ./internal/networkinventory
```

O benchmark sintético não mede o kernel. O teste Linux apenas observa seu ambiente;
não comprova suporte nativo a outras plataformas, aplicação de configurações,
recuperação ou paridade administrativa.
