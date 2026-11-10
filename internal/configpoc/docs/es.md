# Experimento de configuración transaccional

[English](en.md) · [Português](pt.md) · [Diseño y criterios de aceptación](../README.md)

Esta guía corresponde a un entorno local de desarrollo confiable. El experimento
modifica archivos temporales de configuración y estados de componentes simulados.
No configura un firewall, proxy, interfaz de red ni servicio ANDEIVA de producción.
No requiere privilegios root, Docker ni acceso de red a un appliance.

## Ejecutar las comprobaciones

Utiliza Linux con Go 1.27.3 ya instalado y un compilador compatible con el detector
de carreras de Go. WSL sirve para desarrollo; utiliza su sistema de archivos Linux
para las pruebas de persistencia, no un directorio montado desde Windows. Si falta
un requisito, registra el bloqueo; no debilites las pruebas ni instales herramientas
de compilación en el appliance para resolverlo.

Desde la raíz del código fuente:

```bash
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOTELEMETRY=off
go test -race -count=1 -v ./internal/configpoc
go build ./internal/configpoc
```

Registra el commit, la versión de Go, el entorno, la salida completa y el código
de retorno. Una compilación correcta solo prueba que el código compila. Las pruebas
omitidas y los escenarios de fallo no ejecutados no cuentan como aprobados. Los
almacenes temporales pertenecen al harness; nunca uses un directorio de datos del
appliance en su lugar.

Ejecuta el escenario independiente en un directorio privado nuevo del sistema de
archivos Linux:

```bash
umask 077
poc_parent=$(mktemp -d /tmp/andeiva-config-poc.XXXXXX)
go run ./cmd/andeiva-config-poc -state-dir "$poc_parent/state" -iterations 20 > "$poc_parent/report.json"
cat "$poc_parent/report.json"
```

El comando acepta entre 1 y 100 iteraciones y emite un informe JSON con aserciones
del escenario y observaciones de recursos. Requiere una ruta absoluta nueva para
el estado y un usuario Linux sin privilegios. Conserva el directorio y el informe
para inspección. No borra almacenes existentes, instala servicios ni aplica reglas
de motores reales.
Usa una ruta canónica sin `.` ni `..`, separadores repetidos ni enlaces simbólicos.
El directorio padre debe existir y permanecer bajo control confiable; las rutas
inválidas se rechazan antes de crear directorios.

## Transiciones y autorización

`stage` crea Candidate. `validate` lo comprueba sin cambiar Running. `commit`
coordina la aplicación en componentes y solo actualiza Running tras el éxito.
Con una ventana de confirmación, la revisión es provisional hasta `confirm`;
el vencimiento activa la compensación. `save` copia explícitamente Running a
Startup y no puede eludir una confirmación pendiente. `recover` intenta reconciliar
un estado efectivo no confiable. `revoke` es un estado protegido independiente
del guardado ordinario de configuración.

Son operaciones tipadas del servicio ejercitadas por las pruebas, no comandos
implementados en la CLI `andeiva` instalada. Las etiquetas Web, CLI y API utilizan
los mismos permisos del servicio. El harness proporciona identidades confiables;
no prueba sesiones de navegador, autenticación HTTP, MFA ni identidad SSH reales.

Reabrir un proceso y arrancar el sistema son casos diferentes. La recuperación del
proceso utiliza el estado transaccional persistido; el arranque explícito selecciona
Startup. Una transacción sin confirmar revierte de forma conservadora tras el
reinicio. La auditoría y las revocaciones deben persistir sin requerir `save`.
El temporizador funciona dentro del controlador. No hay un watchdog independiente
ni una concesión temporal impuesta por el motor que pruebe el cumplimiento del
plazo mientras el controlador esté caído.

## Fallos y recuperación

Conserva la salida y el comando exacto de una prueba fallida. No elimines bloqueos,
edites el historial, sustituyas hashes ni borres estados para obtener un resultado
aprobado. Si una operación de almacenamiento tiene resultado incierto, detén los
cambios y reabre mediante la recuperación prevista. Si un componente no puede
revertir, informa que requiere recuperación; un estado parcial no es un commit
correcto. Un directorio nuevo sirve para otra prueba aislada, no para sustituir
la recuperación del caso original que falló.

El almacén tiene capacidad finita. Rechazar nuevas operaciones al alcanzar el
límite conserva el historial; no constituye una política de retención o respaldo.
Al reabrir, bajo el bloqueo de escritura, se comprueban todo el historial confirmado,
todas las entradas y la coincidencia entre `staging-v1.owner` y
`.andeiva-stage-v1/owner.json` antes de retirar el único temporal huérfano
`.andeiva-stage-v1/record.tmp`, limitado a 1 MiB. Los metadatos identifican el formato
`andeiva.config.staging.v1` y un `store_id` compartido; la limpieza no depende del
sufijo de archivos temporales de Go. Esta limpieza nunca borra auditoría confirmada.

Los archivos inesperados o ajenos, los temporales antiguos `.pending-*`, los
metadatos incompatibles y la inicialización parcial de propiedad bloquean la
apertura y se conservan. Estos casos no tienen reparación automática. Conserva
el directorio original y la salida del fallo para investigar; no borres ni edites
marcadores, no renombres archivos para introducirlos en el directorio de staging
ni elimines archivos desconocidos para aprobar la recuperación. Un proceso con
el mismo UID o root queda fuera de esta frontera de confianza.

La configuración y los diagnósticos pueden contener información sensible. Mantén
las evidencias privadas y comparte solo lo necesario para reproducir el defecto,
sin credenciales ni datos ajenos al caso.

## Interpretación de resultados

El esquema 3 añade declaraciones canónicas de servicios locales; los esquemas
1/2 conservan sus bytes y hashes exactos y no admiten esas declaraciones. La
migración requiere stage y commit, nunca reescritura automática del journal.
Cambiar servicios locales o seleccionar un rollback histórico que involucre el
esquema 3 exige un plazo de confirmación (30–120 segundos por la frontera
administrada). Si vence el plazo o se reinicia el servicio mientras está pendiente,
se restaura el Running anterior; Save se rechaza hasta confirmar. El rollback
entre revisiones legadas sigue siendo inmediato. El arranque del SO carga Startup
guardado. Estos contratos no demuestran listeners HTTPS/SSH ni aplicación en kernel.

La escritura de archivos, el ciclo de procesos, los bloqueos y la autorización
común pueden ser reales; la aplicación en componentes sigue simulada. Registra
estas categorías por separado. Mide CPU, memoria residente, crecimiento de disco
y latencia para la carga ejecutada. Un benchmark de configuración pequeña no
demuestra throughput de paquetes ni certifica la capacidad del appliance.

Interrumpir procesos, sincronizar archivos y reiniciar no demuestra resistencia a
un corte físico de energía. Este experimento no selecciona SQLite o PostgreSQL,
implementa HA, firma historiales, cifra secretos, proporciona autenticación de
producción ni valida coordinación real de nftables/proxy. Esos gates siguen abiertos.

## Reserva de capacidad: AND01 sigue parcial

Antes de aplicar un commit confirmado o un rollback histórico confirmado, el
coordinador exige espacio para seis registros: dos de activación, hasta dos de
resolución y dos para una recuperación/reapertura. Las escrituras ordinarias,
revocaciones y auditorías de solicitudes rechazadas no pueden consumir los cuatro
registros reservados mientras haya confirmación pendiente. El propietario
autorizado puede confirmar con esa reserva. También se reservan recibos para la
confirmación y una recuperación necesaria; repetir Recover en estado sano no
elude la cuota. El cálculo de bytes utiliza el máximo existente de 1 MiB por
registro, cubriendo el crecimiento del estado y los recibos sin ampliar límites.

El journal mantiene límites de vida útil: 64 MiB, el número configurado de
registros (2.048 por defecto) y 1.024 recibos. Las escrituras pueden detenerse antes
para proteger la reserva. Una auditoría sin capacidad devuelve error de
almacenamiento. Estado, historial y reintentos exactos autenticados siguen
disponibles al alcanzar la cuota si el servicio abierto está sano. No se reparan
journals ya agotados: una reanudación sana con menos de dos registros disponibles
falla antes de añadir un intento o aplicar una revisión. Reaperturas repetidas y
fallos físicos de almacenamiento siguen siendo riesgos acotados por esos límites.
Compactación, retención, ciclo de recibos y gestión de claves requieren otro ADR
revisado. Aquí no se eliminan registros ni se cambia el formato durable.

Ejecuta `go test -race ./internal/configpoc -run TestCapacity` y
`go test ./internal/configpoc -run '^$' -bench BenchmarkCapacityAdmission -benchmem`
en Linux. El benchmark mide solamente admisión en memoria, no RAM del appliance
ni throughput. La prueba de bytes inyecta contabilidad de cuota y escribe registros
reales de tamaño variable; no simula un disco físicamente lleno. Siguen pendientes
el benchmark de recursos en Debian y la validación de fallos físicos.
