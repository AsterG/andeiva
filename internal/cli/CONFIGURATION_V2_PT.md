# Operações de configuração

Os comandos `configuration` exigem um endpoint administrativo v2 autenticado.
O armazenamento selecionado determina se aceita operações de firewall ou o grupo
roteado. Instalar a CLI não migra nem ativa uma configuração.

Use a CA confiável e um arquivo de credenciais individual, acessível somente
pelo proprietário:

```sh
andeiva configuration status --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
cat stage.json | andeiva configuration stage --request-file - --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration validate --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration commit --confirm-seconds 60 --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
```

`stage.json` segue o contrato tipado `OperationRequestV2`: operação `stage` e a
configuração completa de esquema 4 ou 6, conforme a capacidade do runtime. O
esquema4 contém somente políticas e não recebe um plano de rede inventado. Para
esquema6, a CLI deriva a revisão de rede dos dados validados. A admissão preserva a geração global como cadeia decimal exata.
Stage e Validate não ativam tráfego. Commit exige confirmação em 30–120 segundos.

Stage recusa uma Candidate existente. Para substituir ou descartar sua candidata
agrupada, copie o `stage_operation_id` exato de status e escolha explicitamente:

```sh
cat replacement.json | andeiva configuration replace-candidate --expected-candidate-stage OPERACAO_STAGE --request-file - --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration discard-candidate --expected-candidate-stage OPERACAO_STAGE --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
```

`replacement.json` contém `operation: "replace_candidate"` e `config` completo.
A CLI transmite `expected_candidate_stage_operation_id` sem alteração e utiliza
a geração global selecionada para CAS. A substituição preserva a Candidate local;
não evita sua prova de recuperação de acesso. Nenhuma operação altera Running,
Startup ou tráfego. Uma candidata obsoleta continua legível e nunca é substituída
automaticamente. Valide após substituir. Abreviações ambíguas como `r` são
recusadas; `rep`, `rol` e `dis` são prefixos distintos.

Antes de executar, stderr informa `ANDEIVA_OPERATION_ACCEPTED` e o ID durável.
Após uma interrupção, consulte esse ID antes de enviar outra operação:

```sh
andeiva configuration operation --operation-id OPERACAO --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
```

Uma operação aceita pode ser retomada explicitamente com `execute --operation-id`.
A execução não é repetida automaticamente nem substituída por gravações v1.
A sessão é encerrada mesmo em caso de erro; namespaces criados são fechados
após resultados terminais. O código de saída 3 indica que continua aceita.

Confirm usa o ID do Commit original e a revisão composta, consultáveis no estado.
Save salva toda Running. Rollback também exige confirmação:

```sh
andeiva configuration confirm --origin OPERACAO_COMMIT --target REVISAO_COMPOSTA --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration save --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration rollback --target REVISAO_COMPOSTA_SALVA --confirm-seconds 60 --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
```

A ativação do runtime, as regras efetivas, a compatibilidade do estado importado
e a recuperação precisam de validação própria. Testes de transporte e telas com
fixtures não comprovam esses requisitos. Não altere enlaces administrativos com
um runtime não validado. Web/CLI/API compartilham admissão e execução.

Consulte o histórico protegido com `andeiva configuration audit --limit 50` e os mesmos parâmetros de conexão. `--before SEQUENCE` é um cursor exclusivo. Os limites da consulta não implicam um histórico completo; `truncated` indica uma busca incompleta. A leitura não admite nem executa operações de configuração.
