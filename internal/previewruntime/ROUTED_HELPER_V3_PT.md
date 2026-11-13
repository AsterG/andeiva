# Montagem do helper de leitura selecionada

OpenRoutedHelperV3 é uma fábrica do supervisor, não um endpoint ou ativação de
serviços. Recebe quatro diretórios fixados e abre pools somente para leitura.
Verifica identidades, papéis, 18 slots, capacidades e ausência de aliases.

Exige UID do helper, grupo primário IPC, grupos suplementares limitados a IPC e
leitor, NoNewPrivs e exatamente CAP_NET_ADMIN nas cinco máscaras. O grupo leitor
é comum aos quatro diretórios e diferente do grupo primário API. Compara BootID
e namespace reais com metadados confiáveis. Não altera validadores v1/v2.

Compõe leitor selecionado, fonte e sessão v3 existentes. Não exige uma ativação
selecionada antes do primeiro handshake: o novo escritor precisa dessa exclusão
antes de publicar seu Intent de inicialização autorizado. Cada efeito posterior
verifica seleção, G1, reservas, Scope e operação independentemente.

Serve aceita apenas socket herdado e PID API fixados pelo supervisor, usando
credenciais verificadas pelo kernel. Desconectar o controlador não fecha helper
ou guardião. Close cancela canais e fecha leitores próprios; não toca autoridade,
regras, listeners ou namespaces. Os roots são emprestados. O servidor v2 de
compatibilidade deve ficar restrito à leitura durante toda sua vida.

Os testes usam arquivos reais de formato compartilhado, verificam O_RDONLY e
rejeitam substituições, aliases e perfis incorretos; verificam limpeza parcial.
Identidades de fixtures não representam um helper privilegiado real. Motor e
guardião são simulados para testar desconexão e expiração independente. Não
qualificam nftables nativo, lançamento do supervisor, permissões entre três
processos, transporte selecionado completo ou unidades implantadas.

Linux: go test -race ./internal/previewruntime -run TestRoutedHelperV3 -count=1

O transporte preparado `routedKernelV3` executa nft apenas com comandos e três
nomes de tabela fixos no namespace verificado. Recebe lotes gerados pela entrada
padrão. Limita entrada e cada saída a 512 KiB e cada processo a dois segundos
dentro do prazo do chamador. Distingue ausência após consulta completa de falha;
presença não comprova propriedade. Laboratório e helper compartilham o decoder
puro. Rejeita execução no host e enums arbitrários. Não está conectado a uma
unidade implantada; testes nativos de processos, tráfego e consumo estão pendentes.

Para o teste isolado do transporte, compile o binário Linux com
`go test -c -o /tmp/andeiva-preview.test ./internal/previewruntime`. No Debian 13
autorizado, coloque-o em diretório de root com modo 0700 e arquivo 0500; execute como root
`bash packaging/preview/tests/routed-kernel-native.sh --isolated-lab /CAMINHO/PRIVADO/ABSOLUTO/andeiva-preview.test`.
O harness cria três namespaces novos, preserva suas identidades para limpeza e
rejeita CI. Verifica check/apply real, leitura schema4 com revisão confiável,
rejeição de validação inválida e da thread que abandona o namespace. Os descritores
âncora fecham ao executar subprocessos. Não qualifica tráfego ou identidades dos
processos de administração/helper.

Cada subprocesso nft recebe `SIGKILL` se morrer a thread fixada do helper que o
iniciou. Isso limita descendentes após falha abrupta; não desfaz um lote já aceito
pelo kernel. A recuperação deve verificar o estado efetivo e a transação
selecionada antes de admitir novas gravações.

O adaptador restrito sem listeners não inicia nem encerra serviços. Aceita apenas
configurações canônicas sem serviços locais habilitados. Verifica o namespace
fixado e duas capturas completas das tabelas TCP/UDP IPv4/IPv6 do kernel. Rejeita
tabelas ausentes, dados inválidos, listeners TCP e sockets UDP vinculados.
Conexões TCP estabelecidas não são listeners. Habilitar serviços exige o worker
e coletor separados. O teste nativo abre e fecha os quatro tipos de socket e
verifica rejeição e ausência posterior.
