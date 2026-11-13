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
I/O físico simulado. Outro teste nativo Debian 13 executa o leitor sem capacidades
após bootstrap, readback e reinício da API mantendo o helper. Após sair o escritor,
root mantém seu checkpoint lock original: aceita a seleção atual e rejeita um
escopo alheio. Isso não comprova retirada do namespace, prontidão DHCP nem a
barreira de publicação do DHCP em execução.

Usar o isolamento do [guia nativo](routed-launch-native-v3.pt.md) e o modo
`--isolated-selected-preflight-lab` de `packaging/preview/tests/routed-launch-native.sh`.
Exigir PASS de `TestNativeRoutedSelectedPreflightV4` e
`ANDEIVA_NATIVE_LAUNCH_CLEANUP_OK`; SKIP não é evidência. Comparar endereços,
rotas, regras e forwarding do host. Uma execução levou 1,76 s; o harness completo
consumiu 1,883 s de CPU e atingiu 36,7 MiB. São medidas de teste, não orçamentos
do serviço permanente.
