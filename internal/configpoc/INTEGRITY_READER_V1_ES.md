# Inspección de integridad del almacén seleccionado

`CaptureReferenceV1` lee y revalida la cabecera seleccionada acotada, incluso durante una recuperación existente. La tupla sirve para correlación; no autoriza acciones ni declara disponibilidad. `InspectionReference` además rechaza configuraciones con Intent, Pending o RecoveryRequired. Ninguno recorre todo el historial.

`InspectQuiescentV1` admite únicamente el lector de historial completo predeterminado. Antes de G1 comprueba la tupla exacta y la ausencia de trabajo con efectos pendientes. Ejecuta los validadores existentes del grafo completo y de reservas; después revalida selector, registros retenidos, perfil del directorio y las tres instantáneas de pools. Un lector limitado a autorización por acción no puede declarar inspección completa.

El llamador debe mantener la barrera de escritura/publicación de la API y verificar por separado que el guardian está inactivo o en bootstrap. El lector no toma el bloqueo del escritor ni impone ese protocolo externo. Admite operaciones aceptadas y reservas potenciales de cierre cuando la configuración está en reposo; valida sus claims sin ejecutar, vencer, liberar ni reiniciar plazos. Así no exige reintentos del cliente para completar la inspección inicial.

Sólo `complete` sin error califica la tupla inspeccionada. Cancelación, correlación obsoleta o datos no disponibles no la califican. Una lectura acotada exitosa seguida de hash o decodificación canónica inválidos conserva evidencia de corrupción únicamente en esa llamada; produce `fenced` sólo tras revalidar selector sin cambios, reservas y perfil. Errores desconocidos, límites agotados, registros ausentes o perfiles inaccesibles permanecen no disponibles. El lector no persiste ni borra el bloqueo del helper.

Se conservan los límites de grafo, bytes, descriptores y E/S. La clasificación de errores reutiliza el mismo presupuesto, sin otra exploración. No persiste caché entre llamadas. La cancelación es cooperativa: no garantiza interrumpir una operación de filesystem bloqueada. No se introducen publicación, limpieza, llamadas a motores ni autoridad de recolección.

Las pruebas Linux usan almacenes y pools temporales reales con motores simulados. Cubren trabajo aceptado, reserva potencial, Pending/Intent reales, política completa, tuplas obsoletas, cancelación, historial corrupto, perfiles, límites y archivos sin cambios. No califican despliegue, aislamiento nativo entre usuarios, metas de rendimiento ni el planificador completo.

Con Go 1.27.4 y dependencias offline previamente disponibles:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc -run '^TestIntegrityReaderV1' -count=1 -timeout=3m
GOPROXY=off GOSUMDB=off go vet ./internal/configpoc
```
