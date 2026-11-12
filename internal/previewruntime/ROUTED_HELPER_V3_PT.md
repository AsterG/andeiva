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
