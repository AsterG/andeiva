# Perfiles de metadatos del runtime enrutado

`Metadata.Validate()` y el lector legado `ReadMetadata()` siguen admitiendo sólo schema 1. Este perfil describe host, gateway, origen y destino del laboratorio: las cuatro identidades de namespace deben ser distintas y no nulas. Su representación JSON no cambia.

El ensamblaje enrutado usa `Metadata.ValidateRouted()`. Admite el validador schema 1 existente o la selección explícita `RoutedMetadataSchemaVersion` (2):

| Campo | Requisito de schema 2 |
| --- | --- |
| `run_id` | Identidad hexadecimal canónica de 32 caracteres en minúscula |
| `boot_id` | UUID canónico en minúscula, excluyendo el UUID nulo |
| `host_namespace`, `gateway_namespace` | Identidades distintas y no nulas |
| `source_namespace`, `sink_namespace` | Ambos cero; no se inventan namespaces de laboratorio |

Las versiones desconocidas y los perfiles mezclados se rechazan. La ausencia de origen/destino en schema 1 nunca lo convierte en schema 2. Los roles legados rechazan schema 2. El cargador de despliegue debe seleccionar el perfil explícitamente y fijar de forma independiente los descriptores reales de host y gateway; no hay conversión automática.

La validación estructural no otorga autoridad. Se mantienen las comprobaciones de descriptores, procesos, arranque, pares del canal, trabajo seleccionado y guardian. Una solicitud no puede sustituir los metadatos del supervisor. Esta extensión no cambia capacidades, plazos, schemas de configuración ni la red del host.

Verificación con Go 1.27.4 del repositorio:

```sh
go test -race ./internal/previewruntime -run '^(TestRoutedMetadata|TestRoutedHelperV3|TestRoutedAPIV3|TestRoutedLaunchV3|TestRoutedKernelV3)' -count=1 -timeout=3m
go test ./internal/previewruntime -run '^$' -bench '^BenchmarkRoutedMetadataV2Validation$' -benchtime=10000x
go vet ./internal/previewruntime
go build ./...
```

Las pruebas cubren compatibilidad JSON, selección explícita, decodificación estricta, sustitución de identidades y rechazo de contextos de kernel/helper no vinculados. El benchmark mide sólo validación pura, no dimensionamiento del appliance. Este corte no califica despliegue en dos namespaces, tráfico, transferencia de interfaces del host ni recuperación en hardware real; siguen siendo gates de integración. Volver atrás requiere conservar el ensamblaje schema 1, sin forzar metadatos schema 2 en un rol legado.

Una muestra de desarrollo Linux de 10.000 validaciones puras midió 434,7 ns por llamada, 16 bytes y una asignación por llamada. El validador no añade archivos, descriptores, procesos ni cachés retenidas; la asignación corresponde al analizador hexadecimal existente. Estas medidas no califican el rendimiento del appliance.
