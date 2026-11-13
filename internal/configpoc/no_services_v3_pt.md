# Inventário roteado sem serviços locais

O ADR-056 permite uma projeção interna limitada para o candidato roteado.
O inventário local deriva da rede canônica: endereços exatos de LAN e WAN no
perfil estático suportado, ou apenas LAN estática quando WAN usa DHCP.
Não inventa endereço DHCP, define serviços, concede acesso de administração,
cria regras Forward/NAT ou modifica SSH/HTTPS do host.

A exceção exige **zero definições de serviços**, inclusive desabilitadas.
O inventário anterior deve estar vazio ou corresponder exatamente à rede
roteada anterior. Uma origem schema-4 sem rede só autoriza a alteração com
inventário vazio. Políticas com definições de serviços preservam sua revisão
exata e não recebem essa exceção. Um `local_services_config` da API diferente
de Running continua rejeitado, mesmo quando coincide com o resultado derivado.

Stage e Replace do proprietário derivam o candidato sob o bloqueio e as
validações existentes de propriedade e geração. Running e Startup permanecem
inalterados. Commit preserva o snapshot anterior completo para compensação.
Rollback carrega o bundle histórico autenticado e verificado e mantém sua
revisão local original; não reconstrói conteúdo histórico. Prazo de confirmação,
trabalho selecionado, auditoria e recuperação permanecem obrigatórios.

`RoutedNoServicesTransitionV3` é um predicado puro sobre conteúdo e hashes
canônicos; não concede autoridade. Boot/restart devem autenticar os bundles
originais e manter a leitura independente de rede, tabelas e listeners.
O motor agrupado verifica tabelas próprias e observações de listeners antes
dos efeitos; o adaptador nativo limita essas leituras ao namespace retido do
gateway.

Os testes usam coordenador/store e motor agrupado reais com I/O simulado.
Cobrem serviços habilitados e desabilitados, inventário alheio, hashes alterados,
ordem, metadados da API, substituição/concorrência, Startup intacto, rollback
retido e rejeição de listeners/tabelas alheios:

```sh
go test -race ./internal/configpoc ./internal/routedactivation -run '^TestNoServicesV3' -count=1
go vet ./internal/configpoc ./internal/routedactivation
```

Ativação, restart, rollback e medições de recursos no Debian continuam como
gates nativos separados. Estes testes não comprovam comportamento do kernel.
Nenhum motor, serviço, listener, timer, esquema persistente ou dependência é adicionado.
