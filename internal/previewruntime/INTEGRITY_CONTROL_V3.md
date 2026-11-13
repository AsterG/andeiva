# Routed integrity control — English

This increment adds trusted explicit assembly; it does not change the default
full-history profile, installer, launcher or running service. The integrity helper
requires a preprepared private fence root and two readers over identical pinned
store/pool resources: full history for inspection, action closure for effects.
The API factory negotiates the control capability before opening its sole writer.
It rejects a caller-supplied Integrity adapter. Neither API nor caller paths can
prepare or reset the helper's private marker.

`routed_integrity_gate.v1` is an explicit fourth IPC3 capability. Legacy and
integrity sessions reject each other's profile; there is no downgrade. One new
verb, `inspect`, has exact `mode` (`attach` or `check`) and a complete expected
SelectionReferenceV2. Responses echo mode and contain a typed result; a complete
result must match the expected tuple. No request supplies budgets or readiness.
Only this control RPC receives 30 seconds. Effect RPCs retain three seconds,
original Boot/Pending deadlines and all existing resource limits.

Attach independently captures the current tuple before coordinator effects. Its
complete acknowledgement means capture only: helper remains cold/reconciling.
A full quiescent inspection, with physical phase idle/bootstrap before and after,
is the only transition to ready. Interrupted, stale, unavailable and unknown
results never qualify. A stable-corruption result latches RAM and attempts the
private persistent fence before replying. A failed marker sync still returns
fenced; it never reports successful persistence or readiness.

The action source is consulted freshly for every effect. Cold/fenced exceptions
require a separate source capability retaining an opaque reader-issued anchor.
The source captures that token independently at authenticated Attach and compares
its reference with the expected tuple; no wire field reconstructs the token.
Cold resolution validates the original durable continuation and exact deadlines.
Fenced resolution is stricter: no new Arm/Apply/Bootstrap/Resume; compensation
requires an anchored Intent/Pending, and Confirm requires the already selected
original Confirm/Boot Intent, identical to the current Intent. Readback conveys
no permission to apply. Independent guardian rollback does not consult this gate.

A controller owns dispatch through completion, even after a lost client reply.
A replacement handshake fails until inspection drains. A missing authenticated
inspection response yields an empty result plus error, never a fabricated typed
Unavailable acknowledgement. The writer must fence publication on that uncertain
result. Typed incomplete responses are actual drained results.

The API remote adapter exposes separate internal atomic publication and closing
checks. Attach enables correlated closing only, never ordinary publication.
Effect errors and channel closure revoke both; only a new complete full scan
restores publication. These checks are not JSON fields or authorization tokens.

A single runtime-owned scheduler coalesces the 64-publication wakeup and a
60-second timer. The timer also checks unchanged history, because external
corruption need not publish configuration. Failed attempts wait for the next
interval. Runtime.Close cancels and drains the scheduler before closing Service;
a startup-only context cannot silently disable required future inspection.
Helper lifetime/guardian rollback remains independent of API disconnect.

Focused tests use typed SIM/preparation fixtures and real in-process channels,
not kernel traffic. Coverage includes strict negotiation/mode/tuple validation,
Attach without readiness, incomplete/corrupt results, marker failure, publication
revocation, cancelled inspection/lost acknowledgement, dispatch handover drain,
and scheduler coalescing/cancellation. The store/IPC lifecycle uses this actual
gate and explicit full inspections between quiescent requests; network/kernel
transports remain SIM. Default full-reader startup has its own unit coverage.
Native three-process activation, privileged launch wiring and production resource
qualification remain pending. No production readiness is claimed.

```sh
go test -race ./internal/firewallipc ./internal/previewruntime -run TestRoutedIntegrityV3 -count=1
go test -race ./internal/firewallipc -count=1
go vet ./internal/firewallipc ./internal/previewruntime
go build ./...
```

# Control de integridad — Español

Ensamblaje explícito preparado; no modifica el perfil predeterminado, instalador,
launcher ni servicios activos. Requiere fence privado previamente preparado y
lectores full/action sobre los mismos recursos fijados. IPC3 negocia
`routed_integrity_gate.v1` sin fallback. Único verbo `inspect`, modos attach/check,
tuple completo y respuesta con modo correlacionado. Control: 30 segundos;
efectos: tres segundos, sin cambiar plazos originales ni presupuestos.

Attach confirma exclusivamente captura independiente, nunca Ready. Sólo una
inspección completa y quiescente, con estado físico idle/bootstrap antes y después,
habilita Ready. Cancelación, estado stale, falta de recursos o fallo desconocido
no habilitan. Corrupción estable bloquea RAM e intenta persistir fence antes de
responder. Fallo de fsync nunca equivale a persistencia aprobada.

La excepción cold utiliza un token opaco capturado por el lector durante Attach,
correlacionado sin reconstruirlo desde JSON. Valida continuación durable y plazos
originales. Con fence sólo permite compensación de Intent/Pending original,
Confirm ya seleccionado e idéntico al Intent actual y lecturas; nunca nuevos
Arm/Apply/Bootstrap/Resume. El rollback autónomo no consulta este gate. Desconectar API no entrega controller mientras siga una inspección.
Sin ACK autenticado se devuelve resultado vacío y error; un resultado tipado
incompleto sí indica dispatch terminado. Publicación y cierre tienen indicadores
internos distintos: Attach sólo permite cierre correlacionado; errores de efectos
o canal revocan ambos, y sólo full G1 completo restaura publicación.

Un scheduler del runtime combina evento64 y temporizador60s, también sin cambios
para detectar corrupción externa. Tras fallo espera el siguiente intervalo.
Close cancela y drena antes de cerrar Service; cancelar un contexto de arranque
no elimina la inspección futura. Pruebas con store/canales/gate reales y red/kernel SIM; el lifecycle hace full
inspecciones explícitas entre pasos quiescentes. Pendientes launcher privilegiado,
tres procesos nativos y consumo/rendimiento de producción.
Los comandos anteriores reproducen los gates locales.

# Controle de integridade — Português

Montagem explícita preparada; não altera perfil padrão, instalador, launcher ou
serviços ativos. Exige fence privado previamente preparado e leitores full/action
nos mesmos recursos fixados. IPC3 negocia `routed_integrity_gate.v1` sem fallback.
Único verbo `inspect`, modos attach/check, tuple completo e modo correlacionado na
resposta. Controle: 30 segundos; efeitos: três segundos, sem mudar prazos ou limites.

Attach confirma somente captura independente, nunca Ready. Apenas inspeção
completa e quiescente, com estado físico idle/bootstrap antes e depois, habilita
Ready. Cancelamento, stale, indisponibilidade ou erro desconhecido não habilitam.
Corrupção estável bloqueia RAM e tenta persistir fence antes da resposta. Falha de
fsync nunca significa persistência aprovada.

Exceção cold usa token opaco capturado pelo leitor em Attach, correlacionado sem
reconstrução JSON; valida continuação durável e prazos originais. Com fence,
permite somente compensação de Intent/Pending original, Confirm já selecionado
e idêntico ao Intent atual, e leitura; nunca novos Arm/Apply/Bootstrap/Resume.
O rollback autônomo não consulta este gate. Desconexão da API
não transfere controller durante inspeção. Sem ACK autenticado, resultado vazio
e erro; resposta tipada incompleta indica dispatch encerrado. Indicadores internos
de publicação e fechamento são separados: Attach permite somente fechamento
correlacionado; erro de efeito/canal revoga ambos, e só full G1 restaura publicação.

Um scheduler do runtime combina evento64 e timer60s, inclusive sem alterações
para detectar corrupção externa. Após falha espera o próximo intervalo. Close
cancela e drena antes de Service; cancelar contexto inicial não elimina inspeções
futuras. Testes com store/canais/gate reais e rede/kernel SIM; lifecycle realiza inspeções
completas explícitas entre etapas quiescentes. Faltam launcher privilegiado,
três processos nativos e consumo/desempenho de produção. Comandos acima.
