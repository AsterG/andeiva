# Runtime integrity publication barrier

## English

`RuntimeOptionsV2.Integrity` is a trusted, optional assembly dependency. The default remains the full-history runtime. With this dependency selected, the constructor correlates the current canonical selection with the authenticated helper before opening the coordinator. Existing reconciliation and boot/readback must finish before a complete quiescent inspection can make the service available for new administrative work.

`InspectRuntimeV1` retains the sole writer's existing mutex through the helper call and final tuple comparison. It does not inspect during a selected Intent, Pending confirmation or recovery-required state. Accepted catalogue work and potential closing credits are not physical leases and do not prevent inspection. No operation expires, executes or renews merely because it is inspected.

Only a complete result for the exact selection, received before cancellation, qualifies new writes. A fenced result blocks this entire writer; only helper-owned code manages the persistent fence. Unavailable, cancelled and stale results do not qualify writes. The helper contract must retain its dispatch barrier or irrevocably fence the controller before returning from an uncertain call; a context timeout alone cannot stop filesystem I/O.

When an API restart leaves an original live confirmation selected, constructor qualification stays deferred without closing its coordinator timer. A successful authenticated attachment permits only its exact reserved closing path, subject to independent helper authorization; it is not full readiness. A lost/unrecognizable inspection completion fences the entire writer, including trusted identity and maintenance publications. This writer must be closed and recovered through a fresh qualified startup; changing the administrative admission flag cannot clear it.

Qualification becomes due after 60 seconds or 64 successful publications. A capacity-one internal channel wakes trusted runtime assembly after the publication threshold, without a blocking queue or new daemon. Runtime assembly owns periodic scheduling and shutdown. A live confirmation defers full inspection; exact owner/origin/target/deadline validation preserves its reserved confirmation path. It does not authorize ordinary changes or extend the original deadline. Observation and known terminal retries remain distinct from new execution.

These seams do not activate host networking, migrate a store, provision accounts, start a helper or make the complete appliance ready. Tests exercise real temporary storage with simulated engines; the integrated authenticated helper, native lifecycle and traffic still require their own qualification.

## Español

`RuntimeOptionsV2.Integrity` es una dependencia opcional de ensamblado confiable. El modo predeterminado conserva el lector histórico completo. Antes de abrir el coordinador, el constructor correlaciona la selección canónica con el helper autenticado. La recuperación existente y la comprobación de arranque deben terminar antes de habilitar nuevas escrituras mediante una inspección completa en reposo.

La inspección mantiene el mutex del único escritor durante la llamada y la comparación final. No se ejecuta con Intent, confirmación Pending o recuperación requerida. Las operaciones aceptadas y sus reservas potenciales no equivalen a leases físicos. Inspeccionar no ejecuta, caduca ni renueva operaciones.

Sólo un resultado completo de la selección exacta, sin cancelación, habilita escrituras. Un resultado fenced permanece bloqueado en el servicio; la persistencia pertenece al helper. Un timeout no demuestra que una lectura del sistema operativo haya terminado: el helper debe mantener la barrera o bloquear irrevocablemente el controlador antes de devolver una respuesta incierta.

Si un reinicio de la API conserva una confirmación pendiente, la calificación se aplaza sin cerrar su temporizador. El vínculo autenticado permite únicamente el cierre reservado exacto, sujeto a la autorización independiente del helper; no equivale a disponibilidad completa. Perder la respuesta de inspección bloquea todo el escritor, incluidas publicaciones internas de identidad y mantenimiento. La recuperación requiere cerrar ese escritor y realizar un arranque nuevo verificado.

La inspección vence tras 60 segundos o 64 publicaciones satisfactorias. Un canal interno de capacidad uno notifica el umbral sin bloquear; el runtime administra el temporizador y su cierre. Mientras existe una confirmación pendiente, se preserva exclusivamente su cierre reservado, con validación de propietario, origen, destino y vencimiento originales. No se amplía el plazo ni se habilitan cambios ordinarios.

Estos contratos no activan interfaces, migraciones ni servicios por sí mismos. Las pruebas usan almacenamiento temporal real y motores simulados; el helper integrado, el ciclo de vida nativo y el tráfico requieren validación independiente.

## Português

`RuntimeOptionsV2.Integrity` é uma dependência opcional da montagem confiável. O padrão mantém o leitor histórico completo. Antes de abrir o coordenador, o construtor correlaciona a seleção canônica com o helper autenticado. A recuperação existente e a verificação de inicialização devem terminar antes de uma inspeção completa em repouso habilitar novas escritas.

A inspeção mantém o mutex do escritor único durante a chamada e a comparação final. Não ocorre com Intent, confirmação Pending ou recuperação necessária. Operações aceitas e reservas potenciais não equivalem a leases físicos. Inspecionar não executa, expira nem renova operações.

Somente um resultado completo para a seleção exata, sem cancelamento, habilita escritas. Um resultado fenced permanece bloqueado no serviço; sua persistência pertence ao helper. Um timeout não prova o término de uma leitura do sistema operacional: o helper deve manter a barreira ou bloquear definitivamente o controlador antes de retornar uma resposta incerta.

Se um reinício da API conservar uma confirmação pendente, a qualificação é adiada sem encerrar seu temporizador. A vinculação autenticada permite apenas seu fechamento reservado exato, sujeito à autorização independente do helper; não representa disponibilidade completa. A perda da resposta de inspeção bloqueia todo o escritor, inclusive publicações internas de identidade e manutenção. A recuperação exige encerrar esse escritor e realizar uma nova inicialização verificada.

A inspeção vence após 60 segundos ou 64 publicações bem-sucedidas. Um canal interno de capacidade um notifica o limite sem bloquear; o runtime controla o temporizador e seu encerramento. Uma confirmação pendente preserva exclusivamente seu fechamento reservado, validando proprietário, origem, destino e prazo originais. O prazo não é ampliado e alterações comuns não são autorizadas.

Esses contratos não ativam interfaces, migrações ou serviços por si próprios. Os testes usam armazenamento temporário real e motores simulados; helper integrado, ciclo de vida nativo e tráfego exigem validação independente.

## Reproduction

With the repository's pinned Go toolchain and dependencies already available offline:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc \
  -run 'TestRuntimeIntegrityV1|TestIntegrityReaderV1' -count=1 -timeout=3m
GOPROXY=off GOSUMDB=off go vet ./internal/configpoc
```
