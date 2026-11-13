# Planos compensados e liberação de reservas de recuperação

Um Commit Confirmed pode falhar antes de publicar a confirmação pendente. Após verificar a compensação, a operação termina como `failed_rolled_back` sem resultado de confirmação. Seu plano físico mantém a concessão e o prazo originais. Esses campos não são removidos para reutilizar a reserva.

O coordenador v2 preparado registra uma resolução `operation_compensated` versão 2. Ela vincula a operação original, a identificação exata do plano físico, a concessão, o prazo, os estados anterior e alvo e a auditoria protegida de conclusão. O mesmo validador contextual verifica operação, sujeito, domínio, geração, estados e auditoria. Não inventa uma operação Confirm nem um ator de recuperação. As resoluções de confirmação e expiração versão 1 mantêm sua codificação.

O recurso obrigatório persistente `reserve_compensation.v1` é selecionado com a operação final compensada, antes da publicação do arquivo de encerramento. O arquivo e a resolução têm discriminadores explícitos de versão. O recurso permanece após liberar todas as reservas físicas e atravessar checkpoints. Leitores anteriores rejeitam o armazenamento antes de um coordenador aplicar efeitos. A admissão já reserva os bytes desse recurso; cotas lógicas, reservas de encerramento e capacidades dos pools físicos não aumentam.

A liberação continua exigindo o arquivo nos dois estados selecionados exatos e as comparações atômicas originais das reservas físicas. Uma liberação parcial prossegue com a mesma prova. O alvo prospectivo é preservado como evidência: o inspetor só o aceita como estado não ativo quando seu hash canônico completo corresponde ao alvo do plano e existem o recurso e os fatos verificados de compensação. Esse estado nunca é aceito como Running ativo. A inspeção completa percorre as dependências de auditoria e estados.

## Escopo e limites de recuperação

- A correção cobre planos Commit/Rollback compensados cuja concessão de confirmação não chegou a ser publicada. Não adiciona resolução genérica de sistema/inicialização nem confirmação fictícia para operações imediatas.
- Arquivos incompletos versão 1 existentes são rejeitados e preservados. Alguns podem ter liberado uma reserva com o digest anterior; reescrita automática não é suportada. Exigem um procedimento separado de reparo revisado ou restauração. Não remover o recurso, editar objetos, alterar prazos ou apagar auditoria protegida para voltar de versão.
- Novos armazenamentos e migrações voluntárias exigem backups verificados. O binário anterior pode ler um caso legado inalterado, mas rejeita o armazenamento após selecionar o recurso.
- Esta mudança de biblioteca não ativa o appliance, não demonstra recuperação do kernel, não autoriza exclusão protegida nem encerra requisitos de resiliência ao esgotamento do armazenamento. A qualificação nativa e de publicação permanece separada.

## Verificação

Usar Go 1.27.4 do repositório e o cache de dependências preparado:

```sh
go test -race ./internal/configpoc -run '^(TestReserveCompensat|TestReserveCoordinator|TestReserveProfile|TestReserveFuture|TestReserveEnvelope)' -count=1 -timeout=5m
go vet ./internal/configpoc
go build ./...
```

`TestReserveCompensationActualPriorReaderRefusal` exige também `-args -reclaim-old-reader=/caminho/absoluto/prior-configpoc.test`, compilado a partir do código anterior com `TestReclaimPriorReader`. Ignorar esse teste não é evidência de compatibilidade. O predecessor testado é `7fe62a0634ed3de00a652dff95aff31f306ec1ff`.

Os testes usam arquivos temporários e pools reais com motores simulados. Cobrem interrupção do intent, conclusão selecionada antes do arquivo, liberação parcial, saída abrupta do processo, replay imutável, referências ausentes e alheias, diferenças de um nanossegundo, separação entre alvo e estado ativo, fechamento do grafo, recurso persistente e rejeição pelo leitor anterior real. Não simulam perda de energia.

Uma amostra do código serializou a resolução adicional em 839–840 bytes e mediu aproximadamente 1,12 ms e 1.618 alocações por validação contextual no filesystem de desenvolvimento. O recurso modifica uma publicação de estado existente; a resolução acrescenta um objeto imutável. Não são medidas de RAM do appliance nem garantia de desempenho. O teste informa as medições atuais para reprodução.
