# Transporte preparado de operaciones de configuración

[English](OPERATIONS_V2.md) · [Português](OPERATIONS_V2_PT.md)

Este incremento valida un handler HTTPS privado y el contrato del cliente Go.
El router y las capacidades de producción permanecen sin cambios: no activa v2,
no garantiza retención, no realiza cutover ni añade restricciones nuevas a v1.

Reutiliza las verificaciones existentes de TLS, host/origen, sesión, CSRF y origen
Web/CLI/API. ServiceV2 verifica la sesión real y el registro canónico de sujetos
en cada solicitud. Los datos de identidad enviados por el cliente y las cabeceras
de reenvío no conceden permisos. Los viewers no acceden al catálogo ni lo modifican.

El handler preparado contempla exclusivamente:

- `POST /api/v2/config/operation-namespaces`
- `POST /api/v2/config/operations/admit`
- `POST /api/v2/config/operations/{id}/execute`
- `GET /api/v2/config/operations/{id}`
- `GET /api/v2/config/operations?namespace_id=...&state=...&cursor=...&limit=...`
- `POST /api/v2/config/operation-namespaces/{id}/close`

Estas rutas no están registradas por el constructor de producción. No se añade
un endpoint de estado o evidencias. Firewall admite stage, validate, commit,
confirm, save, rollback y recover. `revoke` se rechaza antes de admitirlo porque
el coordinador todavía no lo implementa. Local Services y su vinculación de
pruebas de acceso permanecen fuera de este transporte.

Los cuerpos tienen un máximo de 1 MiB. Se rechazan miembros JSON desconocidos o
duplicados, decimales no canónicos e identificadores que puedan introducir rutas.
Los uint64 nuevos viajan como cadenas decimales, incluidas ambas generaciones.
El resultado histórico de una operación es independiente de `current`, que reúne
la generación/lineage global y la proyección del dominio bajo el mismo bloqueo.
Las páginas vacías o filtradas también incluyen `current`. En v2,
`snapshot.revoked` contiene IDs durables de sujetos retirados, no nombres de v1.

Las funciones de migración en frío inspeccionan fuentes v1 bloqueadas sin replay
ni limpieza. Exigen sujetos, vinculaciones históricas y fingerprints explícitos;
los verifican de nuevo con ambas fuentes bloqueadas antes de publicar. Conservan
los journals originales y seleccionan almacenamiento preparado; no activan el
runtime ni publican Running operativo sin lectura efectiva del coordinador.

## Reproducción

Desde la raíz del repositorio, con Go 1.27.4 en Linux:

```sh
go test -race ./internal/adminapi ./internal/adminclient ./internal/configpoc -run '^(TestPreparedOperationsV2.*|TestOperationsV2.*|TestMigrationServiceV2.*|TestServiceV2AtomicObservations|TestServiceV2Observations.*)$' -count=1 -timeout=10m
go test ./cmd/... ./internal/... -count=1 -timeout=10m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
```

Las pruebas usan archivos temporales y HTTPS de loopback con certificado
verificado. No requieren root ni conexión al appliance, ni modifican namespaces
o reglas reales. El handler utiliza journals v1 reales, migración explícita,
almacenamiento v2 real y **motores simulados**. Comprueba Commit Confirmed,
confirmación, Save, rollback, resultados históricos/actuales, páginas vacías,
RBAC, propiedad, concurrencia y solicitudes hostiles. El cliente utiliza fixtures
de contrato identificadas; no demuestra un despliegue de producción completo.

Validación nativa Debian 13 sin privilegios, procesos focales completos:

| Proceso | Tiempo | CPU | Pico de memoria cgroup |
|---|---:|---:|---:|
| Handler HTTPS preparado | 0,997485 s | 0,233278 s | 15.028.224 B |
| Almacenamiento/migración | 0,360537 s | 0,138744 s | 12.849.152 B |
| Fixtures del cliente | 0,182327 s | 0,098538 s | 13.606.912 B |

La memoria cgroup no equivale a RSS ni al consumo del servicio de producción.
Esto no acredita 5.000 ciclos con motores reales, capacidad física/retención,
cortes de energía, reclamación protegida, paridad Web/CLI/API o cutover. Los gates
de almacenamiento y activación de rutas continúan pendientes.
