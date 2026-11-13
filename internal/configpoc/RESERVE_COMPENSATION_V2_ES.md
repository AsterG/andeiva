# Planes compensados y liberación de reservas de recuperación

Un Commit Confirmed puede fallar antes de publicar la confirmación pendiente. Tras verificar la compensación, la operación termina como `failed_rolled_back` sin resultado de confirmación. Su plan físico conserva el arrendamiento y el plazo originales. No se eliminan esos campos para reutilizar la reserva.

El coordinador v2 preparado registra una resolución `operation_compensated` versión 2. Vincula la operación original, la identificación exacta del plan físico, el arrendamiento, el plazo, las instantáneas anterior y objetivo, y la auditoría protegida de finalización. El mismo validador contextual comprueba operación, sujeto, dominio, generación, instantáneas y auditoría. No inventa una operación Confirm ni un actor de recuperación. Las resoluciones de confirmación y vencimiento versión 1 conservan su codificación.

La capacidad obligatoria persistente `reserve_compensation.v1` se selecciona junto con la operación final compensada, antes de publicar su archivo de cierre. El archivo y la resolución tienen discriminadores explícitos de versión. La capacidad permanece después de liberar todas las reservas físicas y al cruzar puntos de control. Los lectores anteriores rechazan el almacén antes de que un coordinador pueda aplicar efectos. El cálculo de admisión ya reserva los bytes de esta capacidad; no aumenta cuotas lógicas, reservas de cierre ni capacidades de los pools físicos.

La liberación sigue exigiendo el archivo en ambos estados seleccionados exactos y la comparación atómica original de cada reserva física. Una liberación parcial continúa con la misma prueba. El objetivo prospectivo se conserva como evidencia: el inspector sólo lo acepta como instantánea no activa cuando su hash canónico completo coincide con el objetivo del plan y existen la capacidad y los hechos verificados de compensación. Nunca acepta esa instantánea como Running activo. La inspección completa recorre las dependencias de auditoría e instantáneas.

## Alcance y límites de recuperación

- Se corrigen planes Commit/Rollback compensados cuyo arrendamiento de confirmación no llegó a publicarse. No se añade una resolución genérica de sistema/arranque ni una confirmación ficticia para operaciones inmediatas.
- Los archivos incompletos versión 1 existentes se rechazan y preservan. Algunos podrían haber liberado una reserva con el digest antiguo; no se admite reescribirlos automáticamente. Requieren un procedimiento separado de reparación revisada o restauración. No quitar la capacidad, editar objetos, alterar plazos ni borrar auditoría protegida para bajar de versión.
- Un almacén nuevo o una migración voluntaria requieren respaldos verificados. El binario anterior puede leer un caso legado sin cambios, pero rechaza el almacén después de seleccionar la capacidad.
- Este cambio de biblioteca no activa el appliance, no demuestra recuperación del kernel, no autoriza eliminación protegida ni cierra los requisitos de resiliencia ante agotamiento de almacenamiento. La calificación nativa y de publicación es independiente.

## Verificación

Usar Go 1.27.4 del repositorio y la caché de dependencias preparada:

```sh
go test -race ./internal/configpoc -run '^(TestReserveCompensat|TestReserveCoordinator|TestReserveProfile|TestReserveFuture|TestReserveEnvelope)' -count=1 -timeout=5m
go vet ./internal/configpoc
go build ./...
```

`TestReserveCompensationActualPriorReaderRefusal` requiere además `-args -reclaim-old-reader=/ruta/absoluta/prior-configpoc.test`, compilado desde el código anterior con `TestReclaimPriorReader`. Omitirlo no constituye evidencia de compatibilidad. El predecesor probado es `7fe62a0634ed3de00a652dff95aff31f306ec1ff`.

Las pruebas usan archivos temporales y pools reales con motores simulados. Cubren interrupciones del intent, finalización seleccionada antes del archivo, liberación parcial, salida abrupta del proceso, replay inmutable, referencias ausentes y ajenas, diferencias de un nanosegundo, separación entre objetivo y estado activo, cierre del grafo, capacidad persistente y rechazo del lector anterior real. No simulan pérdida eléctrica.

Una muestra del código serializó la resolución adicional en 839–840 bytes y midió aproximadamente 1,12 ms y 1.618 asignaciones por validación contextual en el filesystem de desarrollo. La capacidad modifica una publicación de estado existente y la resolución añade un objeto inmutable. No son medidas de RAM del appliance ni una garantía de rendimiento. La prueba informa las mediciones actuales para reproducirlas.
