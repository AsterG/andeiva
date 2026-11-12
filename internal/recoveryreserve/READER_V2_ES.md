# Acceso preparado de lectura a reservas

La biblioteca incorpora un perfil explícito de lector compartido y observaciones
acotadas de pools v2. No activa IPC agrupado, selecciona políticas, autoriza efectos,
migra el appliance ni completa la resiliencia del almacenamiento.

`PrepareV2` y `OpenV2` conservan 0700/0600. R1 y el formato durable no cambian.
`PrepareSharedV2` exige un directorio vacío previamente provisionado;
`OpenSharedV2` mantiene el lock exclusivo del escritor. No convierten permisos
existentes. Los archivos nuevos se crean exclusivamente y reciben 0640 incluso
con umask 077; una preparación fallida conserva los archivos parciales.

El supervisor confiable proporciona `ReaderAccessV2` versión 1: UID propietario,
GID lector dedicado, dispositivo e inode del directorio. Se exigen directorios
02750 y archivos 0640 exactos, propietario/grupo esperado y ausencia de ACL POSIX
extendida o predeterminada. Se verifican identidad, enlace único, archivo regular
y mismo dispositivo. Consultas ACL no soportadas se rechazan. El lector no puede
ser root y debe pertenecer al grupo lector. Cuentas, credenciales y claves TLS
permanecen fuera de estas raíces y grupos.

`OpenReadOnlyV2` exige además ID, rol, capacidad y cantidad de slots esperados.
Abre descriptores de lectura sin flock, sync, reparación ni publicación.
`Snapshot` compara dos capturas acotadas de ambos bancos y sus contenidos;
`Revalidate` compara otra captura con la evidencia anterior. Bancos desiguales
válidos conservan la semántica de transiciones v2; evidencia parcial, incoherente
o cambiante se rechaza. Inventarios y contenidos devueltos son copias. El snapshot
tiene campos privados y no es un token serializable de autorización.

`CheckDirectory` y `ReadFile` permiten reutilizar las comprobaciones de archivos.
`ReadFile` acepta un nombre ASCII acotado sin ruta y un límite de 1 byte a 1 MiB;
no valida hashes de contenido ni relaciones contextuales del grafo.

El consumidor debe verificar opt-in canónico persistente, selección, trabajo,
finalidad y bindings. Mantiene la barrera del coordinador durante comprobación y
efectos; el supervisor cerca el controlador anterior antes de abrir otro escritor.
La doble lectura no es CAS disco/kernel. El guardian ya armado conserva el plan
verificado de reversión sin depender de nuevas lecturas. La cancelación es
cooperativa, no un plazo duro de E/S. Conversión offline, binarios antiguos y pruebas
reales con tres UID siguen pendientes de integración. No hay conversión automática
ni fallback al perfil privado.

Límites existentes: 32 slots de hasta 1 MiB, `slots + 1` descriptores retenidos y
uno transitorio de directorio. Dos capturas pueden retener cuatro copias del
contenido por slot; el consumidor debe presupuestar los snapshots retenidos.
El lector no añade workers, timers, caché, asignación de disco ni E/S de fondo.
El perfil habitual de planes tiene 18 slots de 16 KiB. El benchmark mide la
biblioteca, no dimensionamiento del appliance ni latencia máxima.

Una ejecución sin privilegios en WSL/Linux con Go 1.27.4 e Intel i7-1370P midió
diez snapshots de un pool lleno de 18 slots de 16 KiB: 2,241 ms/op,
1.377.323 B/op y 7.493 asignaciones/op. Las asignaciones no son RSS del proceso.
Aislamiento Debian, impacto en el appliance y transacción GroupIPC completa
no están medidos aquí.

Reproducir en Linux con Go 1.27.4, cuenta no root y filesystem con ACL POSIX.
Las pruebas utilizan directorios desechables, no el store activo:

```sh
go test -race ./internal/recoveryreserve -count=1 -timeout=3m
go vet ./internal/recoveryreserve
go test ./internal/recoveryreserve -run '^$' -bench BenchmarkReadOnlyV2Snapshot -benchtime=10x
```

La prueba nativa Debian13 pasó con identidades numéricas distintas de escritor,
grupo lector, helper y tercero. El helper leyó un plan con el lock del escritor
activo; no pudo escribir, crear, renombrar, borrar ni leer datos privados del
propietario. El tercero no leyó el pool. No se crearon cuentas ni se modificó red.
Coste del ensayo: CPU0.025398s/pico cgroup20,119,552bytes con hijos; no es sizing
del servicio. No prueba autoridad de selección ni IPC agrupado.

Sólo en laboratorio Linux aislado autorizado, como root para reducir credenciales
de procesos hijos (CI normal omite esta prueba voluntaria):

```sh
go test -c -o reserve.test ./internal/recoveryreserve
ANDEIVA_READER_IDENTITY_LAB=1 ./reserve.test -test.run '^TestNativeReadOnlyV2ThreeIdentities$' -test.count=1 -test.v
```

El lanzador limitado necesita CAP_CHOWN, CAP_FOWNER, CAP_FSETID, CAP_SETUID,
CAP_SETGID y CAP_DAC_OVERRIDE sólo para crear/limpiar la fixture; no son permisos
de los servicios del appliance.
