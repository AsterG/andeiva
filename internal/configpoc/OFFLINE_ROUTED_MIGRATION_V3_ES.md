# Actualización en frío de una migración preparada

`PrepareOfflineMigratedRoutedStoreV3` actualiza únicamente un almacén privado ya preparado por `PrepareMigrationV2`. Conserva el objeto de migración, registros de origen, índices de recibos, asociaciones explícitas de sujetos, linaje y generaciones. No sustituye configuración existente, vuelve a copiar historia, cambia permisos ni invoca motores.

El perfil inicial acotado exige firewall schema 4 y servicios locales schema 3 con acción predeterminada deny, sin reglas de forwarding, servicios ni interfaces. Ambos dominios deben tener Running, Startup y LastGood iguales, sin Candidate, transacción pendiente ni recuperación requerida. Las reglas de firewall existentes se conservan. Otros estados requieren su recuperación o administración autorizada; nunca se descartan ni se reajusta su base automáticamente.

## Autoridad de origen y publicación

El instalador proporciona roots retenidos de destino y de ambas fuentes, sus fingerprints explícitos, los tres pools R2 existentes, presupuesto y una implementación confiable de `OfflineMigrationReadbackV3`. El core bloquea firewall, servicios locales y destino en ese orden; relee las fuentes bajo sus locks existentes, compara fingerprints con la migración copiada y mantiene los locks durante verificación, publicación y cierre del destino. Una fuente modificada se rechaza antes del readback. El instalador también mantiene detenido el escritor administrativo anterior y retenido el namespace del helper observado durante la llamada.

`VerifyMigratedSources` recibe copias canónicas de las revisiones de la migración validada. La implementación productiva debe leer la política efectiva del helper anterior y comprobar ausencia de los recursos del dominio local declarado inactivo. No adopta listeners ajenos ni los presenta como servicios ANDEIVA. Un hash declarado, JSON del cliente, booleano o motor simulado no constituye verificación. El callback no puede reentrar al destino mientras su lock está retenido.

Una publicación selecciona configuración schema 7, auditoría y testigo de verificación del origen, R2, deadlines absolutos, perfil de lector compartido y `configuration.routed-offline-migration.v1`. Ese testigo **no** verifica el nuevo gateway. El coordinador requiere autoridad routed, boot ID confiable, pools reales y deadlines absolutos; la disponibilidad todavía exige Boot y readback físicos. G1 conserva sus validaciones normales de testigos y migración, sin excepción nueva para historia no verificada. Los lectores incompatibles rechazan el feature, que ninguna publicación posterior puede eliminar.

## Interrupción y reversión

Antes de publicar el selector queda seleccionada la migración anterior; pueden quedar objetos inmutables no seleccionados. Una interrupción con `selection.pending` conserva el bloqueo de recuperación existente y no permite reintento silencioso. Tras sustituir el selector, perder la respuesta deja una selección exitosa incierta: reabrir sólo con el perfil compartido previsto y realizar integridad y recuperación Boot física normales. Nunca eliminar el marcador ni reescribir historia para volver atrás. Conservar respaldos y evidencia del intento; el operador puede preparar otro destino independiente mediante la migración autorizada. Esta función no convierte permisos ni implementa un instalador de reversión automática.

## Pruebas y límites

Con Go 1.27.4:

```sh
go test -race ./internal/configpoc -run '^TestOfflineMigratedRoutedV3' -count=1 -timeout=2m
go vet ./internal/configpoc
go build ./...
```

La prueba de compatibilidad necesita `-args -reclaim-old-reader=/ruta/absoluta/prior-configpoc.test`. Compilar la fuente productiva anterior añadiendo sólo el adaptador independiente `offline_routed_migration_prior_linux_test.go`. Primero se prueba lectura del almacén privado original; después se exige rechazo mediante el lector **compartido** anterior. Sin binario explícito ese caso se omite y no queda calificado.

Las pruebas usan journals y pools reales, replay, locks, concurrencia, copias de entrada, cierre G1 completo, requisitos de runtime ausentes, rechazo del verificador, cancelación, fallos de publicación y reapertura. El verificador es un doble unitario explícito: no acredita al proveedor nativo ni el cambio de appliance. No hay cambios de host, aplicación de política, reclamación de espacio ni garantías de cuota, corte eléctrico o rendimiento productivo. La publicación medida añadió siete archivos y 5.839 bytes lógicos en 22,3 ms en WSL; no representa RAM ni espacio físico asignado/libre, y excluye la preparación completa de la migración. La calificación nativa de recursos sigue separada.
