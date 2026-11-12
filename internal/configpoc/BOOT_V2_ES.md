# Recuperación Startup v2 preparada

[English](BOOT_V2.md) · [Português](BOOT_V2_PT.md)

Es una ruta interna inactiva. No la habilitan servicios de producción, API, CLI,
marcadores de arranque ni IPC privilegiado. Requiere una configuración v2 ya
inicializada y no evita las comprobaciones de lectura de la migración.

Un UUID de arranque validado y suministrado por el ensamblado confiable distingue
el arranque del sistema del reinicio de proceso. El reinicio conserva Running y
resuelve operaciones interrumpidas o sin confirmar con su operación y lease
originales. Un nuevo arranque selecciona el contenido guardado en Startup sólo
tras validar y comprobar todos los componentes. Startup no cambia; las
generaciones de dominio y global avanzan. Candidate conserva propietario, base
y revisión, sin aplicación ni cambio de base implícito. Una base obsoleta exige
preparar de nuevo los cambios antes del Commit.

Antes de los efectos se persisten intent, margen contable acotado y la función
obligatoria permanente `boot_startup.v1`. No se fabrica un usuario, recibo de
admisión ni origen de confirmación. Running, auditoría y referencia validada de
arranque completado se seleccionan juntos. Reabrir el mismo arranque comprueba
el estado efectivo sin repetir efectos o selección, incluso si el proceso cayó
antes de escribir un marcador externo. Los lectores v2 antiguos estrictos rechazan
el indicador, que persiste después de checkpoints. Los campos opcionales nulos
conservan la codificación y hashes anteriores.

El adaptador preparado reutiliza el bootstrap único del guardian; Apply normal
requiere lease exacta. Rechaza leases ajenas y comprueba el estado efectivo tras
respuestas perdidas. El callback tipado de recuperación acotada aún no tiene
binding IPC privilegiado. Un arranque parcial conserva el Running seleccionado
anterior y exige el mismo contexto para reanudarse, sin inventar una revisión
verificada. No degradar ni retirar una función obligatoria seleccionada.

**Local Services con Running diferente de Startup se rechaza antes de efectos.**
Su mapper de listeners y evidencias sigue pendiente F. No se omite ningún dominio.
No activar esta ruta hasta validar ensamblado, helper autenticado, recuperación
de servicios locales y arranque real del sistema.

## Reproducción

Con Go 1.27.4 sobre Linux, desde la raíz:

```sh
go test -race ./internal/configpoc ./internal/firewalladmin -run '^(TestV2Boot|TestPreparedStartup)' -count=1 -timeout=5m
go test -race ./internal/configpoc ./internal/firewalladmin ./internal/nftguardian -count=1 -timeout=10m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
```

Las pruebas usan journals temporales reales, motores simulados y guardian dentro
del proceso. Las salidas de procesos hijos comprueban interrupciones alrededor
de intent, efectos, lectura y selección. Cubren arranque repetido, confirmación
pendiente, Candidate inactivo, UUID y registros inválidos, referencia ausente,
presupuesto lógico y rechazo de lectores antiguos después de 64 selecciones.
No prueban nftables, listeners, IPC, reinicio del sistema, pérdida de energía ni
reserva física. No necesitan privilegios. La validación nativa Debian 13 como
UID 1000 aprobó todos los tests seleccionados sin omisiones: coordinador
2.764573 s, CPU 1.307027 s, pico cgroup 23,281,664 B; adaptador de arranque
0.042477 s, CPU 0.014056 s, pico cgroup 5,341,184 B. Son medidas del proceso de
prueba, no RSS ni consumo del appliance. Los UUID fueron entradas inyectadas;
los journals reales y las salidas de procesos hijos usaron motores simulados
persistentes. No se validó reboot del sistema, IPC real ni pérdida de energía.
AND-01/02 y la activación de producción siguen abiertos.
