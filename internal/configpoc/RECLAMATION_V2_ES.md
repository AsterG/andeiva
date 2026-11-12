# Recuperación preparada de páginas de índice nuevas

Este componente interno requiere activación explícita y sólo elimina páginas del índice de operaciones creadas exclusivamente por el writer actual después de activarlo. No está conectado al runtime, API, CLI, temporizadores ni arranque. No elimina auditoría protegida, operaciones retenidas, configuraciones, evidencia de migración ni archivos históricos. AND01/02 siguen abiertos.

El alcance se limita a la vida de un writer. Un registro en memoria conserva como máximo 1.024 identidades de páginas. Al agotarse, las nuevas páginas quedan retenidas sin impedir operaciones ordinarias. El uso genérico de un objeto y la deduplicación invalidan su autorización de eliminación, aunque falle una publicación posterior. Reabrir pierde todo el registro; nombres, hashes y marcador no lo reconstruyen. No hay adopción histórica ni continuación de lotes tras reiniciar.

`enableIndexReclamation` selecciona el campo opcional `reclamation_version: 1` antes de registrar páginas. Cero se omite y conserva la codificación predeterminada; otros valores se rechazan. Publicación y validación de predecesores impiden retirar o degradar el marcador. Las pruebas incluyen Boot, migración y reapertura. El lector estricto anterior rechaza el campo nuevo: no se debe borrar para intentar un downgrade. No existe otra base de datos ni una lista durable creciente por escritura.

`reclaimIndexPages` mantiene el mismo mutex y bloqueo exclusivo del writer durante todo el recorrido acotado y la eliminación. Reutiliza el grafo tipado con validación contextual, seleccionado/predecesores, recibos y dependencias de recuperación. Un cierre incompleto no autoriza borrados. Un cierre completo tampoco basta: cada candidato requiere creación exclusiva comprobada e identidad de archivo regular, propietario, modo, dispositivo/inodo, enlaces, tamaño y contenido intactos. Los nombres se generan internamente respecto del descriptor retenido del directorio.

Cada página eliminada debe ser elegible por sí misma. Una salida del proceso entre eliminaciones no exige continuar un lote; las restantes quedan retenidas al reabrir. La ambigüedad de E/S o integridad bloquea el handle. Cancelación o agotamiento del presupuesto detienen el trabajo sin levantar un bloqueo existente. Se rechaza mantenimiento durante intent de configuración, confirmación pendiente o recuperación requerida.

Bytes e inodos retirados del directorio no equivalen a bloques libres. La contabilidad se reconcilia después de sincronizar el directorio y la admisión sigue observando la capacidad del filesystem. Un archivo eliminado pero abierto puede conservar su asignación. No es una cuota, reserva de recuperación, acuse de exportación protegida ni garantía frente a fallas físicas.

El directorio privado y un único writer cooperativo son condiciones necesarias. Linux no ofrece una operación general de comparar inodo y eliminar atómicamente; no se protege contra un propietario/root malicioso cambiando nombres. El recorrido mantiene el mutex y puede retrasar solicitudes. La cancelación es cooperativa entre llamadas al filesystem, sin plazo estricto ante E/S bloqueada. El walker acotado G1 no demuestra escala para 674.000 archivos. GC concurrente con barrera completa de creación, deduplicación, protección y pins queda pendiente.

## Verificación

Con Go 1.27.4 en Linux/WSL y caché de módulos previamente preparada:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc -run '^TestV2Reclaim' -count=1 -timeout=4m -v
GOPROXY=off GOSUMDB=off go vet ./internal/configpoc
GOPROXY=off GOSUMDB=off go build ./cmd/... ./internal/...
```

Las pruebas usan archivos temporales reales: replay retenido, límites, migración, Boot, sustitución de identidades/enlaces, interrupciones alrededor de unlink/sync, salidas de proceso y archivos eliminados abiertos. La escasez de admisión inyectada no demuestra ENOSPC/EDQUOT nativo. La prueba del lector anterior se omite explícitamente sin su binario; una omisión no constituye evidencia.

Para compatibilidad exacta, extraer `79fcc63a5b9fb88e5e5988e2c5f33739fde7f52a` en un directorio temporal nuevo, copiar únicamente `store_v2_reclaim_prior_linux_test.go` a su `internal/configpoc` y construir allí con `go test -c -o /ruta/absoluta/prior-configpoc.test`. Ejecutar después en la fuente actual:

```sh
go test -race ./internal/configpoc -run '^TestV2ReclaimOldReaderCompatibility$' -count=1 \
  -reclaim-old-reader=/ruta/absoluta/prior-configpoc.test
```

El adaptador utiliza `openV2` de la fuente anterior real. Comprueba lectura predeterminada y rechazo del marcador después de otras 130 publicaciones, sin modificar archivos.

Una muestra inicial WSL con race y 40 ciclos de catálogo retiró 180 páginas / 93.720 bytes nominales, conservando 180 páginas registradas y replay exacto. Un intervalo medido de bloqueo fue de 1,114 segundos. Es una muestra del test de almacenamiento; no demuestra bloques liberados, rendimiento del appliance ni dimensionamiento productivo.

Los binarios Linux iniciales de G2, anteriores a la integración con transacciones locales F2, se ejecutaron después en Debian como UID 1000 con NoNewPrivileges y PrivateNetwork. La suite, incluido el argumento del lector anterior real, pasó sobre journals temporales reales. El tiempo combinado fue de 2,060528 segundos, CPU de 0,830340 segundos y memoria máxima del cgroup de 20.893.696 bytes. Son medidas de aquella carga completa de pruebas, no RSS del appliance ni un benchmark continuo. No se tocó ningún datastore activo. Las salidas de proceso no demuestran seguridad ante pérdida eléctrica. La fuente combinada F2 requiere su propia calificación; presión nativa en volumen finito y continuidad del runtime siguen siendo gates separados. La revisión independiente no encontró hallazgos críticos, altos ni medios en el alcance preparado de G2.
