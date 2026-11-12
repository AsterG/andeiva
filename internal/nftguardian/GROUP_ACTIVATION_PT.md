# Autoridade tipada do grupo de routing

`NewGroup(GroupEngine)` recebe `RoutedActivationBundleV1` e `RoutedTransitionV1`
aprovados. Compartilha o núcleo privado de lease/timer/CAS de Guardian, sem inserir
o composite em `configpoc.Revision` ou criar leases por componente. APIs legacy
e campos wire de State mantêm seus significados.

A montagem confiável fornece um GroupEngine real. `ValidatePlan` é obrigatório:
verifica intent durável selecionado, deadline original, lineage, fechamento
contextual de objetos e reservas antes de timers/efeitos. Formato/hash não é
autorização. Não há validador permissivo padrão ou flag de ativação.

`BootstrapStartup(ctx, transition, target, originalStarted)` exige `BeforeOwned`
físico verificado, sem hash de configuração efetiva. Calcula somente
`originalStarted + 10s`, arma rollback antes de aplicar e respeita esse deadline.
Não afirma que PreviousRunning selecionado estava aplicado. `State.Previous`
fica vazio no baseline físico frio; digest de artefato não substitui hash de
configuração. Root deve selecionar plano real e recursos antes da chamada.
Fences R2/legacy permanecem; bootstrap relativo não se torna compatível.

`ArmUntil` vincula before/target completo já verificado e seu escopo de artefatos.
`ApplyLease`, `ConfirmLease`, `RecoverLease` e `MatchObserved` comparam transição
armazenada e receipt exato. Um Confirm exige readback completo do target físico
e da configuração. Receipt confirmado exato resolve resposta perdida; recover não
reverte cegamente grupo confirmado. Rollback usa BeforeOwned exato com contexto
limitado independente; readback falho bloqueia a autoridade.

Current/ObserveOwned devem ler componentes reais. O engine possui todos os
escritores network/firewall/local e aplica/restaura na ordem deny-first. A fachada
não implementa esse engine, IPC, ativação do coordenador, comandos kernel, provas
de endpoint ou armazenamento. Seu lease fica em memória; perda do helper exige
integração durável/recovery de Root. Sem segundo DB/catalogue/journal ou sucesso
durável não verificado.

```sh
go test -race ./internal/nftguardian ./internal/firewalladmin ./internal/firewallipc ./internal/previewruntime -count=3 -timeout=4m
go vet ./internal/nftguardian ./internal/firewalladmin ./internal/firewallipc ./internal/previewruntime
go build ./cmd/... ./internal/...
```

Testes de grupo usam bundles tipados canônicos reais e resultados de engine
controlados; não qualificam ativação física multi-componente. Pendentes runtime
nativo, endpoints, recursos e perda de processos. Sem mudanças host/manager/DHCP
ou promessas de inspeção, continuidade absoluta, HA ou release do appliance.
