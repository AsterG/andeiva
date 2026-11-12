# Modelo de rede roteada

Preparação interna e inativa: valida IPv4 WAN DHCP/estática, LAN/administração
estática, zonas, uma rota padrão WAN e DNS. Não altera interfaces, rotas,
forwarding, serviços ou regras. Sem bridge, VLAN, PPPoE, NAT ou servidor DHCP.

Decode limita o documento a 64 KiB e rejeita campos duplicados, desconhecidos,
alias de maiúsculas/Unicode e valores adicionais. Canonical preserva bits do host
e gera revisão determinística. Coleções e campos também possuem limites.

A associação persistente usa nome e MAC; o índice é resolvido do inventário atual
confiável e pode mudar após reiniciar. IP observado não comprova concessão DHCP.
Hashes não autenticam nem provam conectividade ou IP livre. IPv6 forwarding deny
expressa requisito ainda não aplicado, não regras efetivas.

O futuro executor exige helper autenticado, RBAC, auditoria, transações e leitura
antes/depois. Deve preservar acesso administrativo anterior até confirmar uma
recuperação segura. A validação não autoriza alterações no host.

Testes reproduzíveis:

```sh
go test -race ./internal/networkplan ./internal/jsoncheck ./internal/nftengine
go vet ./internal/networkplan ./internal/jsoncheck ./internal/nftengine
```

Cobrem revisões, CIDR, conflitos, DNS/gateway, identidade, mudanças legítimas de
índice, ambiguidade DHCP e JSON. Não provam routing/NAT. Integração e consumo real
Debian pendentes. Reversão: remover código inativo, sem recursos runtime residuais.
