# Contrato preparado de configuração roteada

Este pacote contém o modelo canônico IPv4 puro do adaptador roteado isolado.
Não realiza E/S nem autoriza alterações de rede. `routednft` preserva seus aliases
e a identidade do erro; revisões e lotes compilados mantêm os mesmos bytes.

`configpoc.CanonicalRouted` valida um envelope preparado do esquema 6: política
explícita de laboratório, negação padrão, sem regras legadas nem serviços locais.
A entrada normal `Canonical` e os motores atuais de firewall, serviços locais e
simulação o rejeitam. A mudança não ativa leitores, API, coordenador ou runtime
para o esquema 6.

São validados interfaces, zonas, ordem, habilitação explícita, CIDR IPv4 e portas
TCP/UDP. Protocolos não suportados, inspeção obrigatória e referências NAT ou
caminhos ambíguos são rejeitados. O escopo permanece experimental.

Execute os comandos reproduzíveis do [guia principal](README.md) na raiz com a
versão Go fixada pelo projeto. Os testes comparam hashes do compilador anterior,
preservam formatos legados e verificam rejeição pelos consumidores reais.
Compilar para outro sistema não comprova execução nativa. Os testes não alteram
interfaces, regras, rotas ou encaminhamento do host.
