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
