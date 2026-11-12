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
