# Ciclo de vida preparado de reservas, perfil v2

Esta biblioteca interna añade claims exactos, datos inmutables de una sola escritura y slots preasignados reutilizables. No selecciona configuración, autentica administradores, prueba la existencia de un archivo canónico ni activa servicios del appliance. Las API y bytes R1 permanecen intactos; cada lector rechaza el otro formato.

`PrepareV2` exige un descriptor de directorio privado vacío y un rol fijo admission, plan o emergency. `OpenV2` mantiene flock e identidades de archivos; el llamador conserva el descriptor del directorio. Se permiten 1–32 slots y datos de 4 KiB–1 MiB alineados. Los bancos tienen cabeceras de 4 KiB y extensiones preasignadas separadas. El ciclo de vida no crea archivos, trunca asignaciones ni elimina rutas. Una preparación parcial se conserva para inspección.

El perfil R2 de 18 slots debe usar `ClaimClass`: ordinary 0–7, closing 8–15 y system 16–17. No se prestan slots entre clases. Los claims huérfanos permanecen retenidos. `Claim` genérico es una primitiva inferior que no debe utilizar la integración de admisión R2. Los créditos canónicos de cierre, catálogo, namespace, bytes e inodos necesitan su propia integración.

`WriteOnce` vincula datos a un scope tipado y devuelve `BindingV2` inmutable. El reintento exacto es idempotente; cambiar datos o scope produce conflicto. `ReadBound` requiere el binding exacto más reciente, sin aceptar otro banco anterior. `InspectClaimed` devuelve una copia candidata, no un resultado seleccionado. Los instantes de deadline se normalizan a UTC. El formato textual de claims/bindings se redacta, pero su JSON contiene metadatos internos: excluirlos de DTO públicos.

`RetireCAS` exige claim/binding exactos y una prueba estructurada de scope, finalidad, archivo y Current/Previous. **El coordinador debe comprobar la selección canónica real, los bytes archivados, las dependencias y la resolución del lease bajo su lock.** La biblioteca comprueba estructura, hash del scope, identidad y CAS; hashes con formato válido no prueban por sí mismos que exista un archivo. Nunca aceptar estas pruebas desde solicitudes administrativas. No hay callbacks hacia store o autenticación.

El retiro sincroniza y verifica ambos bancos como retired-held, free-prepared y ready. Sólo una pareja ready idéntica permite asignar. Una fase interrumpida reconocida sólo reanuda con la prueba original exacta. Una prueba antigua no puede retirar una época nueva. Bancos corruptos o desconocidos bloquean sin reparación automática ni fallback. Los huérfanos previos a admisión pueden agotar su clase tras interrupciones repetidas.

No se crean workers, timers, conexiones ni acciones de motor. La preasignación no garantiza metadatos, journal, COW, cuotas, medios averiados, filesystem read-only o cortes de energía. Salir de un proceso no equivale a un corte eléctrico. Archivo protegido, finalidad de leases, replay/selección v2, aislamiento físico y continuidad runtime siguen fuera de la biblioteca. AND-01/02 continúan abiertos.

## Reproducción

Linux, Go 1.27.4 y dependencias previamente disponibles:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/recoveryreserve -count=1 -timeout=4m
go vet ./internal/recoveryreserve
go build ./cmd/... ./internal/...
```

Se usan archivos temporales preasignados reales y pruebas canónicas de retiro simuladas. Se verifican más de 64 ciclos de reutilización, clases, scopes/épocas, concurrencia, fallos, salidas reales de proceso, corrupción, identidades/permisos y rechazo cruzado R1/V2. No demuestra archivo canónico real, rollback del kernel ni ENOSPC nativo de esta implementación v2. Medidas de recursos y pruebas nativas de volumen finito siguen pendientes.