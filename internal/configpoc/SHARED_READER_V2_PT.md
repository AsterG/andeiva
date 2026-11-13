# Leitor da configuração selecionada

Biblioteca com adesão explícita para ler configuração v2 e reservas com identidade dedicada somente de leitura. Não inicia helpers, instala permissões, publica endpoints ou concede autoridade de rede.

## Perfil e migração

O perfil privado mantém diretórios `0700` e arquivos `0600`. `PrepareSharedReaderV2` exige configuração selecionada sem transação pendente, publica a característica persistente `shared_reader.v1` e bloqueia o handle privado. Não altera permissões existentes. A abertura privada rejeita o marcador e a compartilhada o exige; leitores antigos estritos rejeitam a característica desconhecida antes dos motores.

Uma conversão offline qualificada separadamente deve preservar bytes e hashes, fixar proprietário e grupo leitor pelo supervisor e estabelecer diretórios `02750`, registros `0640` e lock do escritor `0600`. Não há conversão automática ou downgrade. Somente inodos novos criados exclusivamente recebem alteração de modo. Validadores de descritor rejeitam ACLs, links e proprietário, grupo, modo, dispositivo ou inodo raiz inesperados. Credenciais e chaves TLS ficam fora dessas raízes.

## Autoridade selecionada

`NewRoutedSelectionReaderV2` recebe emprestados a raiz e três pools somente de leitura. Identidade e política vêm do supervisor, nunca do JSON do solicitante. `Observe` retorna par de seleção, hash de estado, linhagem, sequência, geração global e hash de trabalho. `Resolve` compara a referência completa com nova leitura e entrega o plano opaco existente apenas para a ação válida. O hash de trabalho isolado não autoriza nada.

Reutiliza seleção canônica, migração, fechamento G1, trabalho routed e reservas. Não adquire flock de escritor, limpa, publica ou chama motores. Captura e revalida ambos os bancos dos pools e a seleção. Arm/apply exigem intent de ativação; confirm exige intent de confirmação ou boot; compensação/recuperação exige seu intent selecionado. Estado ativo final permite resume e leitura efetiva, não recuperação alheia. O prazo original de boot e o recibo exato do guardian permanecem obrigatórios.

`PrepareView` fornece Current/Startup e a base retida como entradas de preparação, sem afirmar o estado real de interfaces ou listeners. A preparação física precisa de leitura efetiva própria. O supervisor deve manter a barreira de uma única instância escritora durante o efeito e impedir ações de handlers anteriores. Duas leituras não constituem CAS atômico entre disco e kernel.

## Limites e recuperação de espaço

Cada percurso tem orçamentos explícitos de objetos, arestas, profundidade, I/O, bytes e payload ativo. Cancelamento é cooperativo entre operações, sem prazo rígido para I/O do kernel bloqueado. As capturas dos pools mantêm os limites existentes. Hashes de objetos são verificados; revisões semânticas não viram caminhos presumidos.

G2 mantém procedência efêmera, mutex/flock e fechamento completo antes de excluir. Somente verificações de metadados e sync do diretório usam o perfil compartilhado. Não há exclusão protegida, adoção histórica, nova autoridade GC ou outro banco de dados. Reabrir perde a autoridade de exclusão da sessão.

## Reproduzir

Go 1.27.4, cache de módulos preparado, Linux e usuário sem root:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc ./internal/recoveryreserve -run 'TestSharedProfileV2|TestSelectedReaderV2|TestReadOnlyV2Metadata' -count=1 -timeout=3m
go vet ./internal/configpoc ./internal/recoveryreserve
go build ./cmd/... ./internal/...
```

Os testes usam registros temporários reais, conversão explícita das permissões do fixture e intents publicados pelo coordenador; preparação/efeitos são doubles de teste. Não comprovam integração do appliance com três identidades, rede host, IPC completo ou instalação resistente a falhas de energia. Evidência nativa e medições de recursos são relatadas separadamente.

Uma amostra de dez iterações em WSL/Go 1.27.4 de `Observe` sobre fixture temporário migrado mediu 20,737 ms/op, 7.885.193 B/op e 62.973 alocações/op, incluindo G1 e captura/revalidação de reservas. São volume de alocações e latência do fixture, não heap retido, RSS do appliance, capacidade ou meta de produção.

## Reutilização de verificações dentro de uma chamada

`PrepareCurrentView` e `ResolveCurrent` obtêm uma seleção completa nova sob o mutex do leitor. O segundo trata hash do trabalho, linhagem e geração do **escopo do trabalho** como expectativas; essa geração não é a geração global selecionada. Os métodos existentes continuam exigindo a referência completa do chamador. Não há alteração do formato de transporte nem dos prazos.

Somente uma chamada pode reutilizar bytes verificados: até 256 descritores retidos somente para leitura e metade do orçamento existente de payload ativo. Permanecem a decodificação tipada e as verificações contextuais das referências. Antes de retornar, são verificados novamente proprietário/modos/ACL, identidade e tempos do inode retido, bytes exatos, seletor e ambos os bancos de cada reserva. Substituição, unlink, mudanças in-place e cancelamento falham de modo fechado. Nenhum cache sobrevive à chamada.

G1 só reutiliza a validação de snapshot, intent ou recuperação idênticos quando a chave inclui o estado canônico completo e os demais argumentos da validação. Os predicados puros de configuração e destino de inicialização preservam identidades exatas. Até oito resultados imutáveis de trabalho routed são reutilizados somente quando todos os objetos de origem permanecem retidos; seu payload representado é contabilizado contra um quarto do orçamento existente de payload ativo. O plano selecionado final é reconstruído separadamente, com verificações atuais de finalidade, identidade e reservas. Os limites levam a leituras limitadas normais, nunca a autoridade parcial. Essas cotas limitam descritores e payloads, não todo o heap Go nem o RSS do appliance.

Testes negativos focais com Go 1.27.4:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc -run 'TestSelectedCacheV2|TestSelectedReaderV2' -count=1 -timeout=4m -benchtime=3x
```

A otimização reduz verificações repetidas; não remove histórico retido, aumenta orçamentos, amplia o prazo de três segundos do helper nem qualifica desempenho do appliance.

Uma amostra compilada WSL/Go 1.27.4 concluiu o ciclo de armazenamento compartilhado, incluindo transações schema-4/schema-6, reinício do helper e rollback, com registros temporários, reservas e IPC Unix reais e motores físicos simulados. Com `RLIMIT_NOFILE=256`, o teste completo levou 22,96 s; a leitura de confirmação final levou 1,7016 s. O leitor anterior esgotou Validate6 em 3,0007 s. As execuções concluem quantidades diferentes de etapas e não comparam throughput.

O processo compilado bem-sucedido consumiu 22,95 s de CPU de usuário, 5,02 s de sistema e RSS máximo de 29.192 KiB. O fixture reúne os pools do escritor e do helper em um processo, diferente do helper separado previsto. Não mede o appliance Debian nem garante tempos com crescimento do histórico retido. Os testes race validam o comportamento separadamente desta amostra temporal sem race.

A cota efetiva do cache é `min(256, RLIMIT_NOFILE/2, FDs_livres_atuais-32)`. O censo Linux limitado é apenas uma estimativa de capacidade; sua falha desabilita o cache de descritores. Leituras gerais podem ocupar metade dessa cota, deixando espaço para dependências da validação de trabalho routed. Não aumentam o limite do processo nem os orçamentos de percurso. Esgotar descritores nega autoridade; liberar descritores alheios permite uma nova leitura posterior. O wrapper original de carga e o validador de finalidade R2 preservam seu comportamento; somente G1 fornece predicados puros de configuração e cargas imutáveis reutilizáveis, verificando o estado completo de cada invocação e sua finalidade.

Três ciclos completos posteriores passaram com limites soft e hard fixados em 256 e observados independentemente por `/proc`. Entre 60 chamadas de origem, o máximo foi 1,8702 s. O tempo total foi 76,5586 s, CPU de usuário/sistema 85,2268/17,6873 s e RSS máximo de 36.156 KiB. A amostragem de descritores a cada 10 ms observou pico de 204; não demonstra o máximo instantâneo. Este fixture WSL repetido em um processo permanece diferente da qualificação nativa com processos separados.
