# Mapeo preparado de pruebas de Local Services v2

Incluye un resolvedor puro y un libro efímero de pruebas. No habilita operaciones
locales, rutas HTTP/SSH, IPC privilegiado, migración ni cambios del appliance.
V1 conserva su comportamiento. El coordinador v2 sigue rechazando transiciones
locales; las pruebas construyen snapshots explícitos para evaluar el mapeo.

`configpoc.ResolveLocalProofV2` comprueba fingerprint, namespace, sujeto durable,
generación global y revisiones canónicas. Distingue el hash compuesto schema5 del
hash local schema3. Confirm exige origen pendiente real, propietario, lease, plazo
y resultado de origen fijado. Antes de asignar lease, commit/rollback tienen lease
vacía explícita, ligada a la operación y destino exactos. No inventa claves. El
replay final/pendiente sigue siendo una consulta, sin regenerar evidencias.
Una Candidate inactiva de otro dominio puede conservar Base anterior tras boot;
no bloquea el mapeo local ni se modifica. Validate/Commit locales rechazan Base
local obsoleta con conflicto. El resolvedor nunca hace rebase de Candidate.

La entrada es una copia interna confiable, no autorización ni DTO. Los snapshots
de dominio omiten Pending; sus campos separados de confirmación/origen contienen
esa relación. Las revisiones históricas requieren un testigo global retenido ya
verificado: el resolvedor no prueba procedencia. No realiza I/O ni efectos y
devuelve un scope opaco con acceso al destino mediante copias.

`PreparedProofBookV2` reutiliza límites y validadores puros existentes: máximo256
tokens, recuperación20s, endpoints60s, limitados también por ejecución y deadline
pendiente. Guarda hashes de tokens sólo en memoria. Recuperación exige la misma
sesión autenticada; endpoints permiten otra sesión del mismo sujeto y revisión de
credencial. Vincula run, namespace, instancia y ActivationHash local registrados.
Una instancia reemplazada en la misma dirección no es equivalente. Web/API pueden
compartir el receptor HTTPS; la etiqueta no concede autoridad.

Emitir pruebas gestionadas requiere una proyección pendiente publicada y los
receptores reales registrados. El caller confiable debe comprobarlos; Publish no
inspecciona el kernel. Confirm exige una prueba por binding habilitado, sin repetidos;
con todos deshabilitados aún exige recuperación. Reserva atómica y de un solo uso.
Una prueba inválida no bloquea permanentemente el libro. Drift, cierre o reemplazo
del proceso invalidan tokens; nunca se persisten.

## Frontera de integración pendiente

Verificar SessionBinding real de E1 antes del lock del coordinador. ProofIdentityV2
es una observación inmediata, nunca una capacidad cacheada. Bajo el mismo lock de
store, volver a validar sujeto/revisión, operación, generación y mapeo antes de
reservar. Orden: auth liberado, store, libro. El libro no retoma locks de auth/store.
No se permite una ventana entre copiar el estado y reservar la prueba.
El libro no revoca automáticamente una observación de identidad ya copiada; los
tests vuelven a autenticar cada acción tras logout/revocación. Cachearla o
reutilizarla en acciones posteriores viola el contrato. Libros nil, incompletos,
sin inicializar o cerrados rechazan sin panic. Evidencias/identidades/reservas
internas omiten secretos al serializar JSON y formatear diagnósticos.

Consumir tras admisión durable, incluida publicación incierta; liberar sólo cuando
el coordinador pruebe ausencia de admisión/efectos. Replay no reutiliza tokens.
Publicar tras readback verificado y selección durable pendiente; invalidar antes
de activar/recuperar. Apply nunca espera sincrónicamente una solicitud de prueba.
Los guards existentes conservan efectos y recuperación autónoma.

No se conecta esta integración, anuncia capacidad local v2, implementa rollback
local ni garantiza downgrade. El libro preparado no añade presupuesto activo al
runtime. No cierra agotamiento de almacenamiento, retención protegida, cuotas o GC.

## Validación

Autenticación real de sesiones con credenciales temporales generadas y snapshots
explícitos. Negativas de hashes/generación/propiedad/fingerprint, replay, publicación,
instancia antigua, sesiones ajenas/revocadas, caducidad y capacidad; reservas
concurrentes, atómicas y de un solo uso. No prueba conectividad HTTPS/SSH real,
readback del kernel ni ejecución nativa Debian.

```sh
go test -race ./internal/configpoc ./internal/localadmin
go vet ./internal/configpoc ./internal/localadmin
go test ./internal/configpoc ./internal/localadmin -run '^$' \
  -bench 'Benchmark(LocalProofV2|PreparedLocalProofV2)' -benchmem
```

Usar Go fijado y caché preaprovisionada; sin nuevas dependencias. Recursos nativos
e integración completa pendientes. Sin cambios Docker, EKS/Helm, procesos,
listeners ni configuración de despliegue.

Benchmark de desarrollo WSL/Linux de 500 ms: resolvedor107455 ns/op,25369 B/op,
267 allocations; Issue+Reserve+consume de recuperación91345 ns/op,20159 B/op,
222 allocations con libro vacío y94743 ns/op,20157 B/op,222 allocations con255
entradas retenidas. Autenticación fuera del bucle. El binding del fixture codifica
703 bytes y su destino750 bytes; no son máximos de memoria ni dimensionamiento del
appliance. El límite256 se prueba aparte. Sin garantía de rendimiento ni carga nativa.
