# Observaciones de autenticación anónima

Componente Linux preparado, con activación explícita; ningún runtime del appliance
lo habilita. `adminauth.New` conserva la auditoría protegida existente.
[English](README.md) · [Português](README_PT.md).

`adminauth.NewWithAnonymousObservations` clasifica solamente nuevos fallos de
login anteriores a verificar la credencial. Agrega por minuto UTC y dirección
real del socket receptor. Normaliza IPv4 representada como IPv6; no usa puertos,
cabeceras reenviadas, nombres de usuario, credenciales ni tokens como claves.
Intentos internos sin socket y pares inválidos van al contador de desbordamiento
sin atribución. No añade observaciones a otros fallos anónimos de la API.

La verificación exitosa, las denegaciones por límites de login/sesiones después
de verificar la credencial, logout, revocaciones y denegaciones administrativas
siguen en auditoría protegida. Su fallo sigue bloqueando la autorización. Un
fallo del área anónima no autentica al solicitante ni marca como fallida la
auditoría protegida. Ningún evento histórico, incluidas antiguas denegaciones de
login, se reclasifica o modifica. No se autoriza exportar, reconocer o borrar
auditoría protegida.

## Admisión y propiedad

El ensamblador confiable entrega un `os.Root` exclusivo, abierto previamente,
propiedad del proceso y modo 0700, además de un `AdmissionGuard` obligatorio.
`Prepare` exige un área vacía; sincroniza snapshot y política versionados antes
de seleccionar `policy.json` mediante rename atómico. `Open` exige esa selección
y un bloqueo exclusivo existente. Los archivos son regulares, de un enlace,
modo 0600 y del mismo propietario. Rechaza entradas desconocidas, enlaces
simbólicos, datos malformados y versiones no soportadas. El llamador conserva
el descriptor raíz. `Close` detiene y espera al worker, libera el bloqueo y
devuelve los errores de publicación.

`AdmissionGuard.Selection` debe verificar la selección real del runtime, ausencia
de escritores durante la preparación, inventario histórico protegido y copia
idénticos, y exclusión de escritores incompatibles. Después debe verificar la
selección activa exacta. Los hashes identifican el inventario histórico capturado;
no impiden agregar nuevos eventos protegidos. No existe proveedor permisivo ni
integración desplegada de este guard. Un directorio o archivo de política nuevo
no impide por sí solo que un binario antiguo ignore la migración. El runtime
deberá rechazar selecciones incompatibles antes de construir escritores; esa
validación está pendiente. Las pruebas de rechazo cubren esta interfaz, no un
ejecutable antiguo desplegado.

`AdmissionGuard.Capacity` debe acreditar el aislamiento respecto de la auditoría
y recuperación protegidas. Separar directorios y consultar espacio disponible
no crea aislamiento. Este módulo no implementa cuotas, reservas físicas ni una
reserva de auditoría protegida.

Si `Open` no puede recuperar el área anónima, `OpenDegraded` exige una `Selection`
canónica exacta, procedente del estado confiable independiente del runtime,
validada por el guard contra la identidad real del área y la selección compatible.
Nunca deduce la selección de archivos de observación corruptos. No abre archivos
de datos ni crea worker; no puede escribir, borrar o reparar. Agrega únicamente
en memoria acotada e informa `memory_only`, `degraded` y `unknown_gap`;
`allocated_known=false` y `persisted_through` cero evitan inventar mediciones o
historia. La autenticación verificada sigue exigiendo auditoría protegida.
Selección canónica ausente o incompatible impide la admisión; no hay retorno a legacy.

## Límites, publicación y pérdidas

- Máximo 1.440 intervalos y 512 entradas de par/minuto en total. El detalle que
  excede la cardinalidad va a desbordamiento; los totales retenidos continúan.
- Caducidad a las 24 horas desde crear cada intervalo. El límite de cardinalidad
  puede reducir la cobertura. Expiración y descarte por capacidad son visibles.
- Techo de 4 MiB del área propia y snapshots de hasta 512 KiB. Se contabilizan
  bloques Linux de archivos nombrados y directorio; antes de publicar se incluye
  el temporal coexistente y 64 KiB para metadatos, bloques e inodo disponibles.
  Esto no equivale a cuota, reserva frente a terceros ni costo total del sistema
  de archivos.
- Un worker por minuto publica solamente cambios y programa la expiración.
  `Record` no hace I/O. La autenticación legacy no crea ese worker.
- Publicación con temporal nuevo, sincronización y rename. Un resultado incierto
  bloquea nuevas publicaciones hasta reabrir. Un temporal válido no seleccionado
  de la generación siguiente puede eliminarse al reabrir; uno parcial o inválido
  se conserva y bloquea la apertura. Se rechazan cambios externos en la selección.

El informe es un límite inferior, no un registro exacto después de un fallo.
`persisted_through` identifica la última publicación reconocida; `pending`,
`unknown_gap`, `degraded`, desbordamientos y contadores saturables muestran las
limitaciones. Toda reapertura indica una brecha desconocida. No se inventan
cantidades de intentos perdidos sin sincronizar. Las lecturas excluyen detalle
caducado incluso bajo presión. No se garantiza eliminación física mientras el
proceso está detenido o el volumen es de solo lectura. La cancelación es
cooperativa, sin plazo estricto para llamadas al filesystem. Una selección
corrupta nunca se interpreta como un almacén vacío.

La expiración depende de un reloj UTC confiable. Un retroceso del reloj rechaza
nuevas observaciones o marca el informe degradado; no demuestra 24 horas reales
transcurridas entre reinicios o fallos del reloj. Falta calificar esa dependencia.

`Manager.AnonymousObservations` exige sesión admin válida y solo permite lectura.
No añade rutas HTTP ni permisos de escritura. Siguen pendientes activación
Web/CLI/API, presión física real, aislamiento de reservas y rendimiento del
appliance. Este componente no cierra AND01/AND02.

## Pruebas y alcance medido

Con Go 1.27.4 y dependencias preaprovisionadas, desde la raíz:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -race -mod=readonly -buildvcs=false ./internal/authobservations ./internal/adminauth -count=3
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go vet -mod=readonly -buildvcs=false ./internal/authobservations ./internal/adminauth
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go build -mod=readonly -buildvcs=false ./internal/authobservations ./internal/adminauth
go test -mod=readonly -buildvcs=false ./internal/authobservations -run TestObservationsBoundedResourceSample -bench BenchmarkObservationsExistingPeer -benchmem -v
```

Las pruebas incluyen compatibilidad de eventos protegidos, admisión, admin/viewer,
concurrencia, presión mediante guard inyectado, cardinalidad, edad/reloj, archivos
alterados, publicación interrumpida y salida/reapertura de un proceso hijo.
También comprueban login verificado auditado con snapshot corrupto y colección
en memoria admitida independientemente. No prueban pérdida eléctrica ni una
reserva desplegada. Una muestra Linux/WSL con
1.440 intervalos y 512 entradas ocupó un snapshot de 175.945 bytes y 184.320 bytes
asignados observados. El microbenchmark de par existente midió 116,2 ns/op,
16 B/op y una asignación/op. No son RAM del appliance, rendimiento continuo ni
dimensionamiento de producción.
