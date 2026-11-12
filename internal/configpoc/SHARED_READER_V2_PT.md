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
