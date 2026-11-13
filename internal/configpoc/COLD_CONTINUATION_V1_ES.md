# Continuación en frío acotada

`CaptureColdAnchorV1` captura la cabecera canónica seleccionada y devuelve un `RoutedColdAnchorV1` opaco, en memoria y ligado a ese lector. `Reference()` expone sólo correlación; JSON no expone el contenido privado. Capturar no califica el historial ni declara disponibilidad.

`ResolveColdContinuationV1` valida por separado el cierre de autorización actual y relee la selección y el estado originales con el lector acotado y su perfil. Comprueba identidad del trabajo, plazo original, propósito y vínculos durables. Sólo permite compensación, confirmación y lecturas existentes, reanudación de trabajo establecido y Boot del coordinador ligado a la configuración capturada o a su finalización verificada. Nuevos Arm/Apply ordinarios quedan denegados hasta la inspección completa.

El límite entre boots debe conservar configuración fuente, trabajo original y referencias de origen/boot anterior exactos. Boot después de revertir Pending exige además registro final real de recuperación, propietario/origen/lease, proyección exacta de rollback, cadena de auditoría y entrada contextual del índice de recuperación. La finalización ordinaria fallida usa operación inmutable, plan seleccionado y auditoría final. Se compara toda la configuración resultante, incluidos Startup y candidatos. Igualdad de Running no demuestra procedencia. El plazo de Boot sigue siendo Started + 10 segundos original; no se añade duración del cliente ni reinicio del plazo.

El llamador mantiene la barrera del escritor y verifica CAS/readback del recibo físico del guardian. Esta biblioteca no inspecciona listeners ni reemplaza G1 completo. El límite del estado seleccionado acota el ancla codificada retenida; no es una cuota de heap. Las lecturas adicionales consumen los presupuestos existentes por llamada. El ancla no retiene descriptores ni caché de objetos entre llamadas.

Las pruebas usan almacenes/pools canónicos temporales reales y respuestas físicas simuladas. Cubren recuperación de Pending seguida de Boot. La integración de Intent ordinario interrumpido sigue bloqueada por el rechazo existente de R2 al retirar un plan con lease pero sin resolución archivada tras rollback fallido; el integrador conserva la reproducción privada. El lector no evita ese rechazo y las pruebas no califican ese cierre en runtime.

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc -run '^TestColdContinuationV1' -count=1 -timeout=3m
```

Usar Go 1.27.4 y dependencias offline ya disponibles. No se afirma calificación desplegada, de red ni de rendimiento entre usuarios.


## Bloqueo persistente

ResolveFencedContinuationV1 reutiliza el mismo grafo acotado y su validación final. Permite compensación original y lectura efectiva; rechaza Arm, Apply, Bootstrap y Resume. Confirm exige un Intent de confirmación o arranque previamente seleccionado, cuyo contenido tipado completo sigue coincidiendo con el ancla. Un ancla con sólo Pending no autoriza una confirmación nueva mientras existe bloqueo. Esto no elimina el bloqueo ni acredita integridad completa. La corrupción confirmada también bloquea todo el escritor, incluidas publicaciones internas de identidad y mantenimiento.
