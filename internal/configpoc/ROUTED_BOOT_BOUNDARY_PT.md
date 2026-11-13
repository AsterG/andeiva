# Recuperação roteada após reiniciar o sistema operacional

Um BootID novo e confiável é diferente de reiniciar o controlador ou helper. O
coordenador não envia planos do namespace antigo à nova instância nem amplia o
prazo de confirmação anterior. A inicialização carrega Startup e preserva
Candidate, seu proprietário e sua base original.

Para confirmação ou tentativa de inicialização pendente, um descritor privado
tipado retém configuração, trabalho, operação/registro e reserva originais. O novo
boot observa seu namespace realmente vazio, seleciona um novo Intent e utiliza
o prazo original de dez segundos desse novo registro. Pending anterior permanece
internamente até verificar Startup; Running histórico não é apresentado como
confirmado. A API não fica disponível durante a transição.

Somente a finalidade verificada do novo boot permite resolver a contabilidade.
O resultado original da operação é imutável. A auditoria registra
`superseded_by_boot`, não uma restauração do alvo anterior. Ambos os âncoras
selecionados do arquivo e a retirada física são exigidos antes de liberar a
reserva. Um marcador persistente impede interpretações silenciosas de leitores
antigos.

Os testes usam armazenamento e reservas reais com autoridade de grupo simulada.
Não comprovam tráfego, perda de energia ou boot físico. Mesmo BootID, papéis/run
alheios, provas substituídas e prazos expirados são recusados. Um segundo reboot
do sistema com descritor ainda pendente é bloqueado antes de reservar outro slot:
os dois slots de sistema não são ampliados ou reutilizados silenciosamente.
O espaço canônico exigido para inicialização continua obrigatório. Qualificação
com armazenamento totalmente esgotado e métricas nativas são controles separados.

Reprodução Linux: `go test -race ./internal/configpoc -run
'TestRoutedOSBootBoundary|TestReserveEnvelopeMaximumDescriptors' -count=1`.
