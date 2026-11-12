# Inspección de referencias v2 de solo lectura

[English](REACHABILITY_V2.md) · [Português](REACHABILITY_V2_PT.md)

Este inspector interno comprueba el conjunto conocido de referencias alcanzables
desde una selección v2, con presupuestos explícitos de trabajo. No está conectado
a un runtime, API pública ni CLI. No abre un coordinador, aplica políticas,
recupera transacciones, elimina archivos ni genera candidatos para reclamación.

## Acceso y resultado

`inspectReachabilityV2` recibe un `os.Root` ya abierto, un contexto y un
`v2ReachabilityBudget`. En Linux abre `checkpoint.lock` existente en modo de solo
lectura y adquiere un bloqueo exclusivo no bloqueante. Si falta o está ocupado,
devuelve un error; nunca lo crea. Comprueba identidad, propietario, permisos,
tipo y sistema de archivos de la raíz y los archivos. El directorio sigue siendo
privado; la inspección no amplía permisos. Las demás plataformas rechazan esta
inspección del almacenamiento.

El inspector enumera entradas en lotes acotados y valida el par seleccionado y
los segmentos limitados de selecciones requeridos. Sigue referencias tipadas de
estado, índices de operaciones, migración, configuración, auditoría,
recuperación y pruebas de revisión verificada. Las lecturas validan hashes y
estructuras JSON estrictas. Antes de devolver éxito vuelve a comprobar el
selector y la identidad retenida del directorio y del bloqueo. No llama a
`openV2` ni ejecuta sus rutas de recuperación y limpieza.

`Complete=true` indica que comprobó el conjunto conocido de referencias dentro
de los presupuestos y que la selección observada permaneció consistente. **No**
demuestra que se puedan eliminar archivos, un acuse de exportación, una marca
duradera de GC ni espacio reservado para recuperación. El informe no permite
clasificar archivos sin referencias como basura. Los contenidos opacos de
auditoría siguen siendo hojas protegidas y opacas.

Cancelación, presupuesto agotado, referencias ausentes, contenido malformado,
estructuras no admitidas o identidades inconsistentes producen error y
`Complete=false`. Los contadores parciales describen progreso; no son una marca
de seguridad utilizable. Una escritura posterior convierte el informe en una
observación histórica: no concede un bloqueo ni autorización a un futuro recolector.

## Semántica de las referencias

Cada hash tiene el significado definido para su campo. Una identidad semántica
de revisión no es automáticamente el nombre de un archivo que contiene un
envoltorio `Revision`. Las configuraciones embebidas se validan en el objeto que
las contiene. Solo se siguen contenidos canónicos externos mediante los
contratos tipados existentes de escritura y lectura. Las claves del índice de
recuperación no son referencias a objetos.

El recorrido conserva el contexto de cada arista: nivel y prefijo del índice,
estado seleccionado, propósito de la prueba y relaciones de identidad. Reusar
un hash o un nodo visitado no permite omitir la validación en otro contexto.
Un contexto sin resolver o incompatible impide un informe completo.

## Límites de recursos

El llamador establece límites de entradas, objetos únicos, aristas, llamadas de
E/S, bytes leídos, bytes de contenido activo y profundidad. El inspector rechaza
presupuestos inválidos y se detiene al superar un límite admitido. El seguimiento
de objetos y aristas permanece en memoria, acotado por esos límites.

`PeakActiveBytes` mide los bytes de contenido contabilizados; no representa el
heap total de Go, RSS, caché del sistema de archivos ni una reserva física. La
liberación necesaria de descriptores se ejecuta aunque el trabajo se detenga.
La cancelación es cooperativa entre operaciones de archivos: no interrumpe una
lectura bloqueada en el kernel ni garantiza un plazo máximo de reloj.

Esta implementación no califica un historial de 674.000 inodos. El recorrido de
grandes almacenes requiere trabajo separado con memoria externa y mediciones.
Siguen pendientes los benchmarks de CPU, RAM, E/S y latencia del appliance.

## Reproducción y límites de la evidencia

Desde la raíz del repositorio en Linux/WSL, con Go 1.27.4 y dependencias ya
disponibles localmente:

```sh
GOPROXY=off GOSUMDB=off go test -race -mod=readonly -buildvcs=false ./internal/configpoc -run '^TestV2Reachability' -count=1 -timeout=5m
go vet -mod=readonly -buildvcs=false ./internal/configpoc
go build -mod=readonly -buildvcs=false ./internal/configpoc
```

Las pruebas focales usan almacenes temporales reales y motores simulados. Cubren
contenido del journal y contadores de llamadas al motor sin cambios; estados
preparados y Candidate; referencias de commit, confirmación y arranque; bloqueos
ausentes, ocupados o reemplazados; presupuestos y cancelación; archivos ajenos o
malformados; contabilización de lecturas de migración; contexto de aristas y
auditoría opaca. No requieren privilegios ni un appliance activo.

Estas pruebas no demuestran continuidad real del tráfico, reinicio del sistema,
pérdida de energía, cuotas o reservas físicas, reclamación segura ni rendimiento
de producción. No habilitan exportación, acuse ni eliminación de datos
protegidos. AND-01/02 y la activación del runtime siguen siendo gates separados
y abiertos.

La calificación nativa Debian 13 AMD64 como UID 1000 sin capacidades pasó la selección completa TestV2Reachability: 0,449149 s, CPU 0,229975 s y pico de memoria cgroup de 13.561.856 B. Las pruebas preparan estados mediante journals temporales reales y motores simulados; la inspección no llama a los motores. No se cambió ninguna política del kernel, listener ni estado del appliance. El cgroup incluye costes de prueba/caché; no representa RSS de un servicio ni garantiza capacidad. Race completo de configpoc, vet/build, compilación cruzada, SAST y búsqueda de secretos aprobados; revisión independiente sin C/H/M pendientes. Esta evidencia no valida GC, reservas ni AND-01/02.
