# Prazos absolutos preparados do helper

Os verbos internos v2 `arm_until`, `apply_scoped` e `confirm_scoped` preservam
o prazo UTC canônico exato. Aplicação, confirmação e recuperação comparam ID,
hashes e prazo dentro do mutex do guardian. Uma diferença de 1 ns representa
outro recibo e não autoriza ações.

`NewPreparedAbsoluteGuardedEngine` exige uma autoridade absoluta tipada completa.
O adaptador relativo não recebe `ArmUntil`; não há fallback para TTL relativo.
Helpers antigos rejeitam os novos verbos. Nenhuma ativação do runtime ou campo
público Web/CLI/API é acrescentado.

Leituras lentas consomem o tempo restante. O guardian deriva uma expiração
monotônica independente após a leitura. Novas reservas exigem pelo menos
500 ms; vincular novamente um recibo exato existente pode ocorrer com menos
tempo, sem renová-lo. Cancelar/desconectar o controlador não cancela o timer.
Reiniciar o controlador preserva a reserva do helper; reiniciar o helper perde
o estado RAM e exige recuperação journal/bootstrap, sem renovação implícita.

Reprodução: executar `go test -race` e `go vet` em `./internal/nftguardian`,
`./internal/firewalladmin`, `./internal/firewallipc`, `./internal/previewruntime`,
e `go build ./...`. Os testes Linux usam sockets sem privilégios e motores SIM.
Não qualificam nftables real, falha elétrica, integração Boot nem produção.

O coordenador mantém as autoridades exclusivas Pending.Deadline e Boot
Started + 10 s. `RecoverPreviousUntil` recupera o recibo expirado exato após
reiniciar o adaptador, sem adotar outro prazo observado no helper.

A composição preparada pode optar por `v2CoordinatorOptions.GuardDeadlines`.
Commit/Rollback/Recover imediatos selecionam `Intent.guard_deadline` opcional e
a feature persistente `configuration.guard-deadline.v1` atomicamente antes dos
efeitos. A janela de dez segundos começa após validação e imediatamente antes
de selecionar Intent; Accepted/ExecuteBefore e Clock não são substitutos. Não
há novos campos de solicitação nem ativação pública.

A opção a frio recusa Intents imediatos antigos sem prazo original. Leitores
antigos rejeitam a feature; novas composições devem manter a opção. Pending e
Boot recusam autoridade temporal duplicada. PlanIntent e o arquivo tipado mantêm
o prazo exato. R2 conserva limites de 16 MiB/64 inodos, núcleo128 KiB e objetos
256 KiB; a admissão contabiliza o espaço antes de reclamar reservas físicas.

Sem opção explícita, a recusa ocorre antes de objetos/Intent/efeitos, mantendo
a operação já admitida como aceita e o armazenamento disponível. A composição
relativa legada não muda. Confirmação ambígua já concluída no helper mantém a
barreira de recuperação, sem rollback cego ou Running fictício. Nenhum runtime,
tráfego real ou resistência a falha elétrica é habilitado ou qualificado aqui.
