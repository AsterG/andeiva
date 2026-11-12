# IPC v2 preparado para recuperação com escopo

[English](SCOPED_V2.md) · [Español](SCOPED_V2_ES.md)

Este transporte não está selecionado no runtime instalado. Construtores,
mensagens e comportamento v1 permanecem intactos. Não altera API pública,
usuários, unidades, regras do host ou namespaces.

O handshake v2 explícito vincula execução do runtime, instância do helper,
época, domínio fixo e namespace. Exige exatamente `attach_observed.v1` e
`recover_scoped.v1`, nessa ordem. Cada mensagem repete os vínculos e a sequência.
Não existe downgrade automático nem verbo v2 `recovered`. Payloads tipados
rejeitam campos duplicados, com capitalização alternativa ou desconhecidos,
JSON adicional, revisões inválidas e deadlines não canônicos. Permanecem os
limites de 64 KiB e 256 KiB para respostas de observação Local-In.

`attach_observed` compara estado e hash efetivo sob o mutex do guardian. Não
aplica/restaura regras, remove leases, prolonga prazos ou conclui recuperação
durável. Uma fase ativa já vencida, ainda não reconciliada pelo timer, rejeita a
observação sem compensação. Antes da associação somente estado, observação e
associação são permitidos. O bootstrap vazio exato habilita apenas o bootstrap
canônico único; depois exige idle verificado e hash não vazio. Não significa
política vazia do kernel verificada.

`recover_scoped` usa o CAS existente do guardian sobre ID, hashes e deadline
original antes da compensação. Não consome lease substituta, inclusive com os
mesmos ID/hashes e outro prazo. V2 não chama recuperação legacy sem escopo.
Uma lease existente pode ser reassociada abaixo de 500 ms sem rearmar; uma
nova mantém os limites de 500 ms e 120 s.

A sessão admite um controlador antes de criar trabalho de conexão e mantém o
guardian nas desconexões. Épocas aumentam sem reutilização. Falha fatal do listener
fecha o controlador ativo antes de esperar workers. O cliente limita chamadas
a cinco segundos; frames iniciados e operações do helper mantêm três segundos.
Troca perdida, inválida ou vencida fecha o cliente. Mutações não são repetidas
automaticamente e nenhum recibo de sucesso é inventado.

`ConnectV2`/`ServeV2` exigem canal previamente autenticado pela montagem confiável.
Wrappers Unix reutilizam metadata e credenciais do kernel; os herdados comparam
PID/UID/GID esperados. SO_PEERCRED em socketpair identifica o criador, não cada
detentor posterior do FD. Permanecem obrigatórios os guards de procedência,
supervisor, aliases, namespace e privilégios do receptor existente. Não ativa
children de `localruntime`. Exclusão entre processos helper, autoridade/realm
únicos e cutover operacional continuam gates separados. Auditoria protegida,
autoridade de exportação e reservas físicas não são alteradas.

Reprodução Linux/WSL com Go 1.27.4 e dependências offline:

```sh
GOPROXY=off GOSUMDB=off go test -race -buildvcs=false ./internal/firewallipc ./internal/previewruntime ./internal/nftguardian -count=3 -timeout=5m
go vet ./internal/firewallipc ./internal/previewruntime ./internal/nftguardian
go build ./cmd/... ./internal/...
```

Os testes usam sockets Unix privados e herdados reais, guardian real e motores
simulados. Cobrem bootstrap, recuperação, expiração, reassociação curta,
substituição de leases, observação obsoleta, respostas perdidas, framing, peers,
Local-In, admissão em rajada e limpeza após falha do listener. Não comprovam
efeitos reais do kernel/listeners, reinício do SO, falha elétrica ou paridade
instalada. Métricas Debian e ativação aguardam qualificação. Antes da ativação,
rollback remove código preparado sem consumidores; um futuro cutover não
autoriza voltar a escritores v1 com trabalho protegido ainda não resolvido.
