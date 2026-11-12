# Recuperação preparada de novas páginas de índice

Este componente interno exige ativação explícita e remove somente páginas do índice de operações criadas exclusivamente pelo writer atual após a ativação. Não está ligado ao runtime, API, CLI, temporizadores ou inicialização. Não remove auditoria protegida, operações retidas, configurações, evidências de migração ou arquivos históricos. AND01/02 permanecem abertos.

O escopo limita-se à vida de um writer. Um registro em memória mantém no máximo 1.024 identidades de páginas. Ao atingir o limite, novas páginas ficam retidas sem impedir operações normais. Uso genérico de objetos e deduplicação invalidam a autorização de remoção, mesmo que uma publicação posterior falhe. Reabrir perde todo o registro; nomes, hashes e marcador não o reconstroem. Não há adoção histórica nem retomada de lotes após reiniciar.

`enableIndexReclamation` seleciona o campo opcional `reclamation_version: 1` antes de registrar páginas. Zero é omitido e preserva a codificação padrão; outros valores são rejeitados. Publicação e validação de predecessores impedem retirar ou reduzir o marcador. Os testes incluem Boot, migração e reabertura. O leitor estrito anterior rejeita o campo novo: não o apague para tentar um downgrade. Não há outro banco de dados nem lista durável crescente por escrita.

`reclaimIndexPages` mantém o mesmo mutex e bloqueio exclusivo do writer durante toda a travessia limitada e remoção. Reutiliza o grafo tipado com validação contextual, seleção/predecessores, recibos e dependências de recuperação. Fechamento incompleto não autoriza exclusões. Fechamento completo também não basta: cada candidato exige criação exclusiva comprovada e identidade intacta de arquivo regular, proprietário, modo, dispositivo/inode, links, tamanho e conteúdo. Os nomes são gerados internamente em relação ao descritor retido do diretório.

Cada página removida deve ser elegível individualmente. Uma saída do processo entre remoções não exige retomar um lote; as páginas restantes ficam retidas ao reabrir. Ambiguidade de E/S ou integridade bloqueia o handle. Cancelamento ou esgotamento do orçamento interrompem o trabalho sem remover um bloqueio existente. A manutenção é recusada durante intent de configuração, confirmação pendente ou recuperação necessária.

Bytes e inodes retirados do diretório não equivalem a blocos livres. A contabilidade é reconciliada após sincronizar o diretório, e a admissão continua observando a capacidade do filesystem. Um arquivo excluído ainda aberto pode manter sua alocação. Não é quota, reserva de recuperação, reconhecimento de exportação protegida ou garantia contra falhas físicas.

O diretório privado e um único writer cooperativo são condições necessárias. Linux não fornece uma operação geral de comparar inode e excluir atomicamente; os controles não impedem um proprietário/root malicioso de alterar nomes. A travessia mantém o mutex e pode atrasar solicitações. O cancelamento é cooperativo entre chamadas ao filesystem, sem prazo rígido para E/S bloqueada. O walker limitado G1 não demonstra escala para 674.000 arquivos. GC concorrente com barreira completa de criação, deduplicação, proteção e pins continua pendente.

## Verificação

Com Go 1.27.4 no Linux/WSL e cache de módulos previamente preparado:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc -run '^TestV2Reclaim' -count=1 -timeout=4m -v
GOPROXY=off GOSUMDB=off go vet ./internal/configpoc
GOPROXY=off GOSUMDB=off go build ./cmd/... ./internal/...
```

Os testes usam arquivos temporários reais: replay retido, limites, migração, Boot, substituição de identidades/links, interrupções em torno de unlink/sync, saídas de processo e arquivos excluídos abertos. Escassez de admissão injetada não demonstra ENOSPC/EDQUOT nativo. O teste do leitor anterior é explicitamente omitido sem seu binário; uma omissão não constitui evidência.

Para compatibilidade exata, extrair `79fcc63a5b9fb88e5e5988e2c5f33739fde7f52a` em um novo diretório temporário, copiar somente `store_v2_reclaim_prior_linux_test.go` para seu `internal/configpoc` e compilar ali com `go test -c -o /caminho/absoluto/prior-configpoc.test`. Depois executar na fonte atual:

```sh
go test -race ./internal/configpoc -run '^TestV2ReclaimOldReaderCompatibility$' -count=1 \
  -reclaim-old-reader=/caminho/absoluto/prior-configpoc.test
```

O adaptador usa `openV2` da fonte anterior real. Verifica leitura padrão e rejeição do marcador depois de mais 130 publicações, sem modificar arquivos.

Uma amostra inicial WSL com race e 40 ciclos de catálogo removeu 180 páginas / 93.720 bytes nominais, preservando 180 páginas registradas e replay exato. Um intervalo medido de bloqueio foi de 1,114 segundos. É uma amostra do teste de armazenamento; não demonstra blocos liberados, desempenho do appliance ou dimensionamento de produção.

Os binários Linux exatos foram depois executados no Debian como UID 1000 com NoNewPrivileges e PrivateNetwork. A suíte, incluindo o argumento do leitor anterior real, passou com journals temporários reais. O tempo combinado foi de 2,060528 segundos, CPU de 0,830340 segundos e pico de memória do cgroup de 20.893.696 bytes. São medidas da carga completa dos testes, não RSS do appliance ou benchmark contínuo. Nenhum datastore ativo foi alterado. Saídas de processo não demonstram segurança diante de perda de energia. Pressão nativa em volume finito e continuidade do runtime permanecem como gates separados. A revisão independente não encontrou achados críticos, altos ou médios neste escopo preparado.
