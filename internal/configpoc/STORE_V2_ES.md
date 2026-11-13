# Almacenamiento v2: preparación y límites

Estos componentes internos preparan almacenamiento, catálogo durable de operaciones y
migración fría. No están conectados al motor, API, CLI ni Web; no activan Running.
No modifican instalaciones v1 ni cierran AND-01/02. Las CA, credenciales y evidencias
efímeras no forman parte del catálogo.

Los objetos inmutables se seleccionan atómicamente con copia anterior. La búsqueda
exacta usa tres páginas acotadas y un objeto de operación, sin mapa global en RAM.
Los identificadores se vinculan a sujeto, namespace y lineage. La reutilización de
slots exige retiro explícito, retención cumplida y ausencia de operaciones fijadas.
Los reintentos no ejecutan efectos ni renuevan la retención.

La migración bloquea ambos dominios originales y el destino, valida sus diarios sin
abrir el servicio y conserva schemas, hashes, Startup, generaciones y recibos.
Rechaza estados pendientes, orígenes clonados y vínculos ambiguos. Publica una única
selección preparada de secuencia 1; las fuentes originales permanecen intactas.

Los presupuestos de bytes/inodos son contables, no cuotas ni reservas físicas. No
existe aún GC físico ni exportación/acuse protegido. El historial sigue ocupando
disco y puede impedir nuevas admisiones. No se promete resistencia a cortes eléctricos.

## Contabilidad física y margen de admisión

En Linux, v2 mide bloques asignados a archivos mediante `fstat` (`st_blocks` en
unidades de 512 bytes), asignación del directorio e inodos, incluido el directorio.
Reconstruye los contadores al abrir bajo bloqueo y los actualiza incrementalmente;
no recorre el catálogo por admisión. Cuenta ambos selectores mientras coexisten y
no cobra dos veces un objeto idéntico ya verificado. Los presupuestos configurados
limitan tanto uso lógico como asignación física observada.

Antes de admitir consulta bytes/inodos disponibles con `fstatfs` sobre el descriptor
validado del directorio. Conserva las reservas ajenas y agrega margen para redondeo
y crecimiento del directorio. Una falta conocida devuelve limited sin emitir una
operación, ocupar slot/reserva, publicar estado ni llamar al motor. Solo lectura o
métricas inválidas devuelven unavailable. Estado verificado, consultas retenidas y
reintentos terminales siguen disponibles; integridad o publicación incierta
mantienen el bloqueo. Una consulta de espacio exitosa no elimina ese bloqueo.

Es una observación con margen estimado, **no una reserva física**. Otros escritores,
cuotas, metadatos o errores posteriores pueden impedir publicación y recuperación.
La disponibilidad del filesystem sigue contando bloques de selectores eliminados
que permanezcan abiertos. No agrega fallocate, cuotas, GC, borrado de historial
protegido, cambios de autenticación/auditoría ni activación runtime. Continúan
pendientes continuidad con volumen lleno, pruebas físicas y cierre AND-01/02.

Con dependencias preaprovisionadas sin red:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -mod=readonly -buildvcs=false -race ./internal/configpoc -run '^TestV2Physical' -count=3
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -mod=readonly -buildvcs=false ./internal/configpoc -run '^$' -bench '^BenchmarkV2PhysicalPreflight$' -benchmem -count=3
```

Las pruebas cubren asignación distinta del tamaño lógico, directorio, selectores
temporales, archivos parciales/sparse, overflow, presión antes de efectos,
reservas propias, lecturas verificadas y reapertura. Métricas inyectadas no prueban
ENOSPC/EDQUOT/EROFS reales. El preflight midió 4,925–4,930 microsegundos,
812–828 bytes y 10 asignaciones por llamada en un directorio temporal WSL Linux
amd64; no es dimensionamiento del appliance ni prueba de pérdida eléctrica.

Pruebas Linux con la versión Go indicada por el repositorio:

```sh
go test -race ./internal/configpoc -run '^TestV2' -count=1 -timeout 10m
ANDEIVA_CONFIG_V2_ENDURANCE=1 go test -race ./internal/configpoc -run '^TestV2DurableCatalogue5000Lifecycles$' -count=1 -v -timeout 35m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
```

El segundo comando mide 5000 ciclos del catálogo, no 5000 transacciones de motores.
Las pruebas de fallo/proceso no equivalen a pérdida eléctrica. La recuperación del
preparado debe conservar fuentes e historial: no borrar archivos desconocidos ni
seleccionar manualmente una revisión. El cutover, downgrade guard, readback global,
paridad administrativa y continuidad con disco lleno siguen pendientes.


### Presión v2 sobre copias

Sólo en Debian 13 de laboratorio autorizado, compilar `go test -c ./internal/configpoc`
y el inspector `andeiva-storage-lab`; preparar el perfil inactivo según su guía.
Como root, usar binarios verificados y propiedad de root:

```sh
bash packaging/preview/tests/storage-pressure.sh --authorized-debian-v2-volumes \
  "$TEST_BINARY" "$TEST_SHA256" --isolated-storage-only \
  "$INSPECTOR" "$INSPECTOR_SHA256" "$VOLUME_ID"
```

El modo admite exclusivamente bytes, inodos y archivos borrados aún abiertos.
Verifica originales y copias; el worker recibe el alcance config y el ejecutable
por descriptores, con UID/GID 1000, sin grupos adicionales/capacidades y con NNP.
Los demás dominios permanecen root-only. ENOSPC real debe rechazar la admisión sin
Apply ni cambio de selección; lookup/replay y Save/reapertura posteriores pasan.
Los motores son simulados. Los tres casos pasaron en Debian: disponibilidad de
bytes/inodos cero y bloques retenidos hasta cerrar. Originales, sentinelas y
limpieza verificados. Total 2,952 s / CPU 2,236 s / pico cgroup 553.398.272 bytes,
incluida caché. No prueba v2 sólo lectura, cuotas/reserva física, reclamación de
auditoría, continuidad del dataplane real ni cortes eléctricos; AND-01/02 siguen
abiertos. El caso readonly del fixture de volúmenes anterior no pertenece a v2.

La presión por bytes dejó disponibilidad cero; tras liberar el archivo de relleno
quedaron 112.132.096 bytes. La presión por inodos alcanzó cero inodos libres con
111.476.736 bytes todavía disponibles. El archivo borrado pero abierto mantuvo
disponibilidad cero hasta cerrarlo; después se observaron 111.075.328 bytes.
Son medidas del filesystem de esta corrida sobre copias. El pico cgroup incluye
caché; no es RSS del proceso, heap de la aplicación ni dimensionamiento productivo.

Véanse las [reservas de recuperación transaccional](RECOVERY_RESERVES_V2_ES.md) para la integración interna de pools/coordinador y sus pruebas pendientes.
# Preparación inicial sin conexión

`PrepareOfflineRoutedStoreV3` acepta únicamente un directorio privado vacío,
tres reservas existentes y configuraciones canónicas vacías: firewall schema4
con denegación predeterminada y servicios locales schema3. Guarda referencias
declaradas y auditoría `offline_seed / prepared`, sin acreditar aplicación física.
La marca persistente `configuration.routed-offline-seed.v1` exige un lector
compatible. El runtime requiere autoridad real, identidad de arranque, reservas
y plazos; debe reconciliar y comprobar el kernel antes de estar disponible.
La excepción inicial del recorrido de integridad no crea una revisión verificada
y no es válida en generaciones posteriores. El instalador convierte permisos
sin escritores activos. Un destino no vacío nunca se reinicializa, tampoco tras
una interrupción. Los appliances existentes necesitan la migración con historial;
esta preparación no demuestra una instalación ni un despliegue completos.
