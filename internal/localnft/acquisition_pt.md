# Controle Local-In de aquisição DHCP

Implementação de desenvolvimento sob ADR-063; a validação integrada da renovação está pendente.

A leitura aceita representações numéricas equivalentes da família IP. Esta regra baseada em UDP exige manter IPv4: portas não implicam uma família IP. Somente um payload IP tipado permite omitir a condição de família redundante correspondente.

O motor roteado deriva uma regra da rede selecionada canônica quando sua WAN usa DHCP: IPv4 recebido nessa WAN, UDP da porta 67 para a porta 68. A regra integra a tabela INPUT própria `andeiva_local` e sua leitura completa. WAN estática e rede roteada ausente não possuem essa regra. A política INPUT continua drop; outras interfaces, famílias, protocolos e portas não recebem autorização dessa regra.

A aquisição pode recuperar-se sem concessão vigente. Portanto, não exige estado conntrack, endereço IP nem prazo de concessão. O cliente mantido valida as transações DHCP; o roteador anunciado não é presumido como servidor DHCP. Não concede acesso administrativo nem forwarding. Identidade, época, prazo original e recuperação da concessão/R2 permanecem, assim como procedência do serviço, inventário de sockets e drenagem de processos.

O compilador recebe a revisão canônica da rede pela composição interna autorizada, nunca uma interface livre ou fragmentos nft do solicitante. A leitura recompila a revisão e rejeita recursos ausentes, alterados ou adicionais. Mudanças da rede recompilam a tabela local mesmo com revisão local igual, removendo a admissão anterior no rollback. A retirada do serviço continua exigindo drenagem real e ausência física; o compilador não gerencia processos.

Testes: `go test -race ./internal/localnft ./internal/routedactivation`; `go vet ./internal/localnft ./internal/routedactivation`; `go build ./internal/previewruntime`; `GOOS=windows GOARCH=amd64 go build ./internal/previewruntime`. Usam compilação pura e o motor real com I/O de kernel/rede simulado; não equivalem a DHCP nativo. Adiciona uma regra/contador por WAN DHCP habilitada, sem novo processo, temporizador, conjunto ou persistência. Validação e recursos nativos pendentes. Sem alterações Docker, Compose, EKS/Helm ou perfis instalados.
