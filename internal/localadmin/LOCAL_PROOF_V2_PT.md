# Mapeamento preparado de provas de Local Services v2

Inclui um resolvedor puro e um livro efêmero de provas. Não habilita operações
locais, rotas HTTP/SSH, IPC privilegiado, migração ou alterações do appliance.
V1 mantém seu comportamento. O coordenador v2 ainda rejeita transições locais;
os testes constroem snapshots explícitos para avaliar o mapeamento.

`configpoc.ResolveLocalProofV2` verifica fingerprint, namespace, sujeito durável,
geração global e revisões canônicas. Distingue o hash composto schema5 do hash
local schema3. Confirm exige origem pendente real, proprietário, lease, prazo e
resultado da origem fixado. Antes da atribuição, commit/rollback têm lease vazia
explícita vinculada à operação e destino exatos. Não inventa chaves. Replay final
ou pendente continua uma consulta, sem regenerar evidências.
Uma Candidate inativa de outro domínio pode manter Base anterior após boot;
não bloqueia o mapeamento local nem é alterada. Validate/Commit locais rejeitam
Base local obsoleta com conflito. O resolvedor nunca faz rebase de Candidate.

A entrada é uma cópia interna confiável, não autorização nem DTO. Snapshots de
domínio omitem Pending; os campos separados de confirmação/origem contêm essa
relação. Revisões históricas exigem testemunho global retido previamente verificado:
o resolvedor não prova procedência. Não realiza I/O ou efeitos e retorna um scope
opaco com acesso ao destino por cópias.

`PreparedProofBookV2` reutiliza limites e validadores puros existentes: máximo256
tokens, recuperação20s, endpoints60s, também limitados pela execução e pelo prazo
pendente. Guarda hashes dos tokens apenas em memória. Recuperação exige a mesma
sessão autenticada; endpoints permitem outra sessão do mesmo sujeito e revisão de
credencial. Vincula run, namespace, instância e ActivationHash local registrados.
Outra instância no mesmo endereço não é equivalente. Web/API podem compartilhar
o receptor HTTPS; o rótulo não concede autoridade.

A emissão gerenciada exige uma projeção pendente publicada e receptores reais
registrados. O chamador confiável deve verificá-los; Publish não inspeciona o kernel.
Confirm exige uma prova por binding habilitado, sem duplicatas; com todos
desabilitados ainda exige recuperação. Reserva atômica e de uso único. Prova inválida
não bloqueia permanentemente o livro. Drift, fechamento ou substituição do processo
invalidam tokens; eles nunca são persistidos.

## Fronteira de integração pendente

Verificar SessionBinding real de E1 antes do lock do coordenador. ProofIdentityV2
é observação imediata, nunca capacidade em cache. Sob o mesmo lock do store,
revalidar sujeito/revisão, operação, geração e mapeamento antes de reservar. Ordem:
auth liberado, store, livro. O livro não retoma locks de auth/store. Não pode haver
janela entre a cópia do estado e a reserva da prova.
O livro não revoga automaticamente uma observação de identidade já copiada; os
testes autenticam novamente cada ação após logout/revogação. Guardar em cache ou
reutilizar a observação em ações posteriores viola o contrato. Livros nil,
incompletos, não inicializados ou fechados rejeitam sem panic. Evidências,
identidades e reservas internas omitem segredos no JSON e nos diagnósticos.

Consumir após admissão durável, inclusive publicação incerta; liberar somente quando
o coordenador provar ausência de admissão/efeitos. Replay não reutiliza tokens.
Publicar após readback verificado e seleção durável pendente; invalidar antes de
ativar/recuperar. Apply nunca espera sincronamente por uma solicitação de prova.
Os guards existentes mantêm os efeitos e a recuperação autônoma.

Esta integração não está conectada, não anuncia capacidade local v2, não implementa
rollback local nem garante downgrade. O livro preparado não adiciona orçamento
ativo ao runtime. Não resolve esgotamento de armazenamento, retenção protegida,
quotas ou GC.

## Validação

Autenticação real de sessões com credenciais temporárias geradas e snapshots
explícitos. Negativos de hashes/geração/propriedade/fingerprint, replay, publicação,
instância antiga, sessões alheias/revogadas, expiração e capacidade; reservas
concorrentes, atômicas e de uso único. Não prova conectividade HTTPS/SSH real,
readback do kernel nem execução nativa Debian.

```sh
go test -race ./internal/configpoc ./internal/localadmin
go vet ./internal/configpoc ./internal/localadmin
go test ./internal/configpoc ./internal/localadmin -run '^$' \
  -bench 'Benchmark(LocalProofV2|PreparedLocalProofV2)' -benchmem
```

Usar Go fixado e cache pré-provisionado; sem novas dependências. Recursos nativos
e integração completa pendentes. Sem alterações Docker, EKS/Helm, processos,
listeners ou configuração de implantação.

Benchmark de desenvolvimento WSL/Linux de 500 ms: resolvedor107455 ns/op,25369 B/op,
267 alocações; Issue+Reserve+consume de recuperação91345 ns/op,20159 B/op,
222 alocações com livro vazio e94743 ns/op,20157 B/op,222 alocações com255
entradas retidas. Autenticação fora do loop. O binding do fixture codifica703 bytes
e seu destino750 bytes; não são máximos de memória nem dimensionamento do appliance.
O limite256 é testado separadamente. Sem garantia de desempenho ou carga nativa.
