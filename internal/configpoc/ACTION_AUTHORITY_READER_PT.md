# Leitor do fechamento de autorização

[English](ACTION_AUTHORITY_READER.md) · [Español](ACTION_AUTHORITY_READER_ES.md)

O leitor selecionado mantém G1 completo como comportamento padrão.
`SelectionReaderOptionsV2.Policy = SelectionActionAuthorityV2` é uma escolha
explícita da montagem confiável; nenhuma fábrica do appliance a habilita.
Não é opção do usuário, API, ambiente ou mensagem IPC.

O perfil valida a seleção completa e as dependências que autorizam a operação
atual: configuração canônica, Candidate, operações e testemunhos referenciados,
auditoria tipada, trabalho, baseline, recuperação, BootBoundary e todas as
reservas ativas. Consulta somente arquivos históricos consumidos por essas
referências e exige fatos finais tipados. Auditoria opaca do catálogo não
comprova uma operação do motor transacional.

Cada objeto consumido permanece retido até a verificação final, mesmo quando a
cache de descritores está cheia. Objetos sem descritor retido são reabertos para
comparar identidade, permissões, ACL e bytes. Memória e leituras são cobradas dos
limites existentes; esgotamento ou alteração rejeita a autorização. Não há cache
de autoridade entre solicitações nem aumento de prazos.

Esse perfil não comprova a integridade do histórico alheio à operação. G1 completo
continua obrigatório para integridade, retenção e GC. Antes de habilitar o perfil
no runtime são necessários G1 completo na inicialização, bloqueio persistente de
novas alterações ao detectar corrupção e agendamento seguro de inspeções. O
bloqueio deve preservar o dataplane conhecido e o rollback já autorizado. Esses
controles ainda não foram integrados; não se comprova o orçamento RPC de três
segundos nem execução nativa desse perfil.

As provas usam arquivos e armazenamentos reais com motores simulados ou limitados
à preparação. Uma comparação retira um objeto histórico alheio ao fechamento:
o leitor de autorização mantém seu escopo e G1 detecta a corrupção. Isso não
autoriza apagar o objeto nem afirmar integridade completa.

```sh
go test -race ./internal/configpoc -run TestActionReaderV2 -count=1
go test -race ./internal/configpoc -run TestSelectedReaderV2 -count=1
go test -race ./internal/configpoc -run TestSelectedCacheV2 -count=1
go vet ./internal/configpoc
go build ./...
```

Uma prova separada com armazenamento/IPC Unix reais seleciona esse perfil após
G1 completo sem coordenador aberto nem publicações ativas; os handles compartilhados
das reservas já estão abertos. Com kernel/rede simulados passou no detector de
corridas e nos prazos RPC originais de três segundos: 56,58 s total e máximo
observado de resolução 1,883935121 s. Verifica Boot4, Candidate/Validate,
Commit/Confirm/Save, ativação roteada, reinicialização do helper e rollback
inverso. Não habilita fábricas do appliance nem comprova tempos nativos ou os
controles de integridade pendentes.

```sh
go test -race ./internal/previewruntime \
  -run '^TestRoutedIPCV3ActionReaderSharedStoreLifecycle$' -count=1 -timeout=100s -v
```
