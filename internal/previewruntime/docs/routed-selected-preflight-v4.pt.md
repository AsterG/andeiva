# Leitor privado da seleção

Root inicia um leitor fixo sem capacidades, com identidade helper e grupo leitor.
Ele herda quatro diretórios somente leitura e dois pipes privados. PID e início
de pai/filho e um nonce novo vinculam a resposta limitada. Uma leitura com falha
não publica resultado válido.

Retirement lê CURRENT e histórico completo por ObserveRetirementSourceV3. DHCP
resolve o trabalho selecionado e seu bundle DHCP canônico, depois revalida a
referência. O resultado não concede autoridade: root mantém a barreira de
publicação até concluir o efeito. Caminhos, identidade, executável ou leases em
cache enviados pela API não são aceitos.

Testes unitários cobrem processo, codec e armazenamento selecionado real com
I/O físico simulado. Lançamento root e ciclo nativo continuam pendentes; o leitor
não comprova retirada do namespace nem prontidão DHCP.
