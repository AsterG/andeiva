# Guards preparados de activación v2

[English](ACTIVATION_V2.md) · [Português](ACTIVATION_V2_PT.md)

Este adaptador es preparación, no activación del runtime. No cambia rutas de
producción, configuración de autenticación, mensajes IPC privilegiados ni el
ámbito de namespaces. El ensamblado real deberá utilizar el wrapper protegido;
los Engine sin guard siguen representando únicamente simulaciones.

`PreparedGuardedEngine` reutiliza Engine, ActivationGuard y State/Current/Arm/Confirm
de LeaseAuthority. El callback de recuperación confiable utiliza la operación de
recuperación existente del helper. No introduce ejecutables o rutas seleccionados
por el cliente, verbos privilegiados nuevos ni bypass administrativo.

El coordinador persiste el intent exacto antes de armar el helper. Los cambios
inmediatos utilizan la operación como lease; los commits confirmados utilizan su
lease persistida. Apply requiere ese ámbito armado exacto. La lectura efectiva de
todos los componentes precede a Confirm y a la publicación del resultado. Las
respuestas perdidas sólo se concilian mediante recibo, lease y revisiones exactos;
un estado idle no basta. Los commits sin cambio de reglas también crean un recibo.

Retomar una lease pendiente no la rearma ni extiende su plazo, incluso durante
los últimos 500 ms. Las leases nuevas conservan un mínimo de 500 ms. El timeout
del helper no depende del proceso API, de la sesión ni del sujeto.

El rollback utiliza la recuperación existente del helper después de validar
lease, revisiones y estado efectivo. Una confirmación fallida puede recuperarse
cuando se comprueba la reversión del helper: se restaura el contenido anterior,
avanzan los contadores de dominio/global, se conserva Startup y se seleccionan
atómicamente el resultado fallido, auditoría vinculada y liberación del pin de
origen. No se reescribe el resultado histórico del commit original.

Si el helper ya confirmó el destino y la publicación durable es incierta, se
bloquean las escrituras sin inventar rollback ni éxito. La reapertura permanece
indisponible hasta una recuperación cualificada por separado. No se eliminan
temporales desconocidos ni se reinician leases ajenas.

## Validación

Desde la raíz del repositorio, con Go 1.27.4:

```sh
go test -race ./internal/firewalladmin -run '^TestPreparedGuard' -count=1 -timeout=5m
go test -race ./internal/firewalladmin ./internal/configpoc -count=1 -timeout=10m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
```

Las pruebas Linux usan journals v1 reales, migración en frío explícita,
coordinador v2 real, guardian restringido existente y **motores simulados**.
Comprueban commits inmediatos/confirmados, confirmación tardía, respuestas perdidas,
aplicación parcial, leases ajenas, timeout independiente, reaperturas repetidas y
una colisión real de archivo temporal después de confirmar el helper. No requieren
root, reglas reales ni conexión al appliance. La validación nativa Debian 13 ejecutó los 10 tests
seleccionados sin omisiones, como UID 1000 y sin capabilities: tiempo 0,586653 s,
CPU 0,273888 s y pico de memoria cgroup 12.656.640 B. Se utilizó guardian en el
mismo proceso, motores simulados y journals temporales reales. Es consumo del
proceso de prueba, no RSS ni consumo del servicio; no acredita IPC privilegiado real.

Esto no valida el ensamblado IPC/runtime privilegiado, tráfico nftables real,
evidencias de Local Services, aplicación de Startup durante un arranque del SO,
garantías físicas de almacenamiento o cortes de energía. Arranque del SO y reinicio
del proceso siguen siendo casos distintos; la transición adicional no se implementa
aquí. AND-01/02 y los gates de activación permanecen abiertos.
