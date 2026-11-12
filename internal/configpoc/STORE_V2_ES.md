# Almacenamiento v2: preparación y límites

Estos componentes internos preparan almacenamiento, catálogo durable de operaciones y
migración fría. No están conectados al motor, API, CLI ni Web; no activan Running.
No modifican instalaciones v1 ni cierran AND-01/02. Las CA, credenciales y evidencias
efímeras no forman parte del catálogo.

Los objetos inmutables se seleccionan atómicamente con copia anterior. La búsqueda
exacta usa tres páginas acotadas y un objeto de operación, sin mapa global en RAM.
Los identificadores se vinculan a sujeto, namespace y lineage. La reutilización de
slots exige retiro explícito, retención cumplida y ausencia de operaciones fijadas.
Los reintentos no ejecutan efectos ni renuevan la retención.

La migración bloquea ambos dominios originales y el destino, valida sus diarios sin
abrir el servicio y conserva schemas, hashes, Startup, generaciones y recibos.
Rechaza estados pendientes, orígenes clonados y vínculos ambiguos. Publica una única
selección preparada de secuencia 1; las fuentes originales permanecen intactas.

Los presupuestos de bytes/inodos son contables, no cuotas ni reservas físicas. No
existe aún GC físico ni exportación/acuse protegido. El historial sigue ocupando
disco y puede impedir nuevas admisiones. No se promete resistencia a cortes eléctricos.

Pruebas Linux con la versión Go indicada por el repositorio:

```sh
go test -race ./internal/configpoc -run '^TestV2' -count=1 -timeout 10m
ANDEIVA_CONFIG_V2_ENDURANCE=1 go test -race ./internal/configpoc -run '^TestV2DurableCatalogue5000Lifecycles$' -count=1 -v -timeout 35m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
```

El segundo comando mide 5000 ciclos del catálogo, no 5000 transacciones de motores.
Las pruebas de fallo/proceso no equivalen a pérdida eléctrica. La recuperación del
preparado debe conservar fuentes e historial: no borrar archivos desconocidos ni
seleccionar manualmente una revisión. El cutover, downgrade guard, readback global,
paridad administrativa y continuidad con disco lleno siguen pendientes.
