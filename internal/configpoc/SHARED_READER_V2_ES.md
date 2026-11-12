# Lector de configuración seleccionada

Biblioteca de activación explícita para leer configuración v2 y reservas con una identidad dedicada de sólo lectura. No inicia helpers, instala permisos, publica endpoints ni concede autoridad de red.

## Perfil y migración

El perfil privado conserva directorios `0700` y archivos `0600`. `PrepareSharedReaderV2` exige una configuración seleccionada sin transacción pendiente, publica la característica persistente `shared_reader.v1` y bloquea el handle privado. No cambia permisos existentes. La apertura privada rechaza el marcador y la compartida lo exige; lectores antiguos estrictos rechazan la característica desconocida antes de los motores.

Una conversión offline cualificada por separado debe preservar bytes y hashes, fijar propietario y grupo lector desde el supervisor y establecer directorios `02750`, registros `0640` y lock del escritor `0600`. No hay conversión automática ni downgrade. Sólo se cambia el modo de inodos nuevos creados exclusivamente. Los validadores de descriptor rechazan ACL, enlaces, propietario, grupo, modo, dispositivo o inodo raíz inesperados. Credenciales y claves TLS quedan fuera de estas raíces.

## Autoridad seleccionada

`NewRoutedSelectionReaderV2` recibe prestados la raíz y tres pools de sólo lectura. Identidad y política proceden del supervisor, nunca de JSON del solicitante. `Observe` devuelve la pareja de selección, hash de estado, linaje, secuencia, generación global y hash de trabajo. `Resolve` compara toda la referencia con una lectura nueva y entrega el plan opaco existente únicamente para la acción válida. El hash de trabajo aislado no autoriza nada.

Reutiliza selección canónica, migración, cierre G1, trabajo routed y reservas. No adquiere flock de escritor, limpia, publica ni llama motores. Captura y revalida ambos bancos de los pools y la selección. Arm/apply requieren el intent de activación; confirm, el intent de confirmación o boot; compensación/recuperación, su intent seleccionado. El estado activo final permite resume y lectura efectiva, no una recuperación ajena. Se preservan el plazo original de boot y el recibo exacto del guardian.

`PrepareView` entrega Current/Startup y la base retenida como entradas de preparación, sin afirmar el estado real de interfaces o listeners. La preparación física necesita lectura efectiva propia. El supervisor debe mantener la barrera de una única instancia escritora durante el efecto e impedir que actúen handlers anteriores. Dos lecturas no constituyen CAS atómico entre disco y kernel.

## Límites y reclamación

Cada recorrido tiene presupuestos explícitos de objetos, aristas, profundidad, I/O, bytes y payload activo. La cancelación es cooperativa entre operaciones; no impone un plazo duro a I/O del kernel detenido. Las capturas de pools conservan sus límites existentes. Se comprueban hashes de objetos; no se convierten revisiones semánticas en rutas supuestas.

G2 conserva procedencia efímera, mutex/flock y cierre completo antes de borrar. Sólo cambian validación de metadatos y sync del directorio según el perfil. No se añade borrado protegido, adopción histórica, autoridad GC ni otra base de datos. Reabrir pierde la autoridad de borrado de la sesión.

## Reproducir

Go 1.27.4, caché de módulos preparada, Linux y usuario sin root:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc ./internal/recoveryreserve -run 'TestSharedProfileV2|TestSelectedReaderV2|TestReadOnlyV2Metadata' -count=1 -timeout=3m
go vet ./internal/configpoc ./internal/recoveryreserve
go build ./cmd/... ./internal/...
```

Las pruebas usan registros temporales reales, conversión explícita de permisos del fixture e intents publicados por el coordinador; preparación/efectos son dobles de prueba. No acreditan integración del appliance con tres identidades, red host, IPC completo ni instalación resistente a cortes. La evidencia nativa y las medidas de recursos se publican por separado.

Una muestra de diez iteraciones en WSL/Go 1.27.4 de `Observe` sobre un fixture temporal migrado midió 20,737 ms/op, 7.885.193 B/op y 62.973 asignaciones/op, incluido G1 y captura/revalidación de reservas. Son volumen de asignaciones y latencia del fixture, no heap retenido, RSS del appliance, capacidad ni objetivo de producción.

## Reutilización de verificaciones dentro de una llamada

`PrepareCurrentView` y `ResolveCurrent` obtienen una selección completa nueva bajo el mutex del lector. El segundo trata hash del trabajo, linaje y generación del **ámbito del trabajo** como expectativas; esa generación no es la generación global seleccionada. Los métodos existentes siguen exigiendo la referencia completa del llamante. No cambia el formato de transporte ni los plazos.

Sólo una llamada puede reutilizar bytes verificados: hasta 256 descriptores retenidos de sólo lectura y la mitad del presupuesto existente de payload activo. Se mantienen la decodificación tipada y las comprobaciones contextuales de las referencias. Antes de devolver, se verifican otra vez propietario/modos/ACL, identidad y tiempos del inode retenido, bytes exactos, selector y ambos bancos de cada reserva. Reemplazo, unlink, cambios in-place y cancelación fallan de forma cerrada. La caché no sobrevive a la llamada.

G1 sólo reutiliza la validación de un snapshot, intent o recuperación idénticos cuando su clave incluye el estado canónico completo y los demás argumentos de validación. Los predicados puros de configuración y destino de arranque conservan identidades exactas. Se reutilizan hasta ocho resultados inmutables de trabajo routed sólo si todos sus objetos fuente siguen retenidos; su payload representado se carga contra un cuarto del presupuesto existente de payload activo. El plan seleccionado final se reconstruye por separado, con comprobaciones actuales de propósito, identidad y reservas. Al alcanzar límites se usan lecturas acotadas normales, nunca autoridad parcial. Estas cotas limitan descriptores y payloads, no todo el heap Go ni el RSS del appliance.

Pruebas negativas focales con Go 1.27.4:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc -run 'TestSelectedCacheV2|TestSelectedReaderV2' -count=1 -timeout=4m -benchtime=3x
```

La optimización reduce verificaciones repetidas; no elimina historial retenido, aumenta presupuestos, amplía el plazo de tres segundos del helper ni acredita rendimiento del appliance.

Una muestra compilada WSL/Go 1.27.4 completó el ciclo de almacenamiento compartido, incluidas transacciones schema-4/schema-6, reinicio del helper y rollback, con registros temporales, reservas e IPC Unix reales y motores físicos simulados. Con `RLIMIT_NOFILE=256`, la prueba completa tardó 22,96 s; la lectura de confirmación final tardó 1,7016 s. El lector anterior agotó Validate6 a los 3,0007 s. Las ejecuciones completan cantidades distintas de pasos y no comparan throughput.

El proceso compilado exitoso consumió 22,95 s de CPU usuario, 5,02 s sistema y RSS máximo de 29.192 KiB. El fixture reúne los pools del escritor y del helper en un proceso, a diferencia del helper separado previsto. No mide el appliance Debian ni garantiza tiempos ante crecimiento del historial retenido. Las pruebas race validan comportamiento por separado de esta muestra temporal sin race.

La cota efectiva de caché es `min(256, RLIMIT_NOFILE/2, FDs_libres_actuales-32)`. El censo Linux acotado es sólo una estimación de capacidad; si falla, deshabilita la caché de descriptores. Las lecturas generales pueden ocupar la mitad de esa cota y dejan espacio para dependencias de validación de trabajo routed. No aumentan el límite del proceso ni los presupuestos de recorrido. Agotar descriptores deniega autoridad; liberar descriptores ajenos permite una lectura nueva posterior. El wrapper original de carga y el validador de finalidad R2 conservan su comportamiento; sólo G1 proporciona predicados puros de configuración y cargas inmutables reutilizables, comprobando el estado completo de cada invocación y su finalidad.

Tres ciclos completos posteriores pasaron con límites blando y duro fijados en 256 y observados independientemente mediante `/proc`. Entre 60 llamadas fuente, el máximo fue 1,8702 s. El tiempo total fue 76,5586 s, CPU usuario/sistema 85,2268/17,6873 s y RSS máximo 36.156 KiB. El muestreo de descriptores cada 10 ms observó un pico de 204; no demuestra el máximo instantáneo. Este fixture WSL repetido en un proceso sigue siendo distinto de la cualificación nativa con procesos separados.
