# Transporte de renovação DHCP idêntica

Os pares confiáveis negociam explicitamente `routed_dhcp_same_effective.v4`, além
de DHCP selecionado, inventário e integridade. O cliente antigo não pode enviar
`dhcp_renew`; a requisição contém apenas hashes de Work e snapshot. A resposta
contém a concessão autenticada ou erro de recuperação. O transporte não valida
sozinho a igualdade L3 nem ativa a renovação.

Somente esse perfil permite dez segundos em apply/open/withdraw/retire/renew.
Clientes antigos e leituras mantêm três segundos; contextos menores e cancelamento
limitam a espera do cliente. Timeout não prova ausência de efeitos ou compensação
concluída. A incerteza invalida o canal. Não altera prazos de lease, Confirm ou
recuperação e não adiciona processos, sockets ou armazenamento.

Reproduzir: `go test -race ./internal/firewallipc` e
`go vet ./internal/firewallipc`. Inclui negociação e prazos com conexões reais em
memória e relógio virtual. Não qualifica renovação nativa ou desempenho.
