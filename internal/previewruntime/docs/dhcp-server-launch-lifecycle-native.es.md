# Calificación del ciclo de vida del lanzador DHCP LAN

Estado: fixture preparado; ejecución nativa y cifras CPU/RAM pendientes. No
activa el producto, transacciones seleccionadas, WAN, forwarding ni NAT. No
repite ni acredita DORA/RENEW. La prueba invoca el lanzador y el rol sellado
reales, con gateway aislado y dos slots exactos; WAN permanece vacío.

La preparación exige Kea real con usuario dedicado, capacidades exactas,
AppArmor stock en enforcement, identidad padre/pidfd/start y socket AF_PACKET
propio sobre el ifindex LAN observado. Tener un handle de lanzamiento no basta.

ADR-075 sustituye el protocolo privado por la versión2. El padre de confianza
prepara exactamente dos árboles de montaje separados desde los descriptores
existentes de configuración y concesiones, antes de crear el namespace del
hijo. El hijo valida todos los slots mediante syscalls antes de crear archivos
con poller: FD3–9 conservan sus funciones, FD10/11 llevan los árboles y FD12/13
los pins exactos de cgroups. El bootstrap sellado liga identidades ordenadas y
procedencia del padre; rechaza peers antiguos o malformados. Configuración es
de sólo lectura y las concesiones siguen en lectura/escritura sobre los mismos
inodos; ambos montajes exigen nosuid/nodev/noexec antes y después del traslado.
No hay fallback por rutas, copia del almacén operacional para transferirlo,
aumento de capacidades ni activación del dispatcher de producción. Se conservan
las copias privadas acotadas existentes para validar con LFC; el montaje que
sirve DHCP usa el directorio operacional original. Pasó el reproductor aislado del
kernel; la calificación del ciclo completo y su delta de recursos siguen pendientes.

El disable se verifica **antes de apagar el supervisor**: Stop y drenaje,
pidfds muertos, hojas sin miembros, cero sockets UDP/RAW/PACKET/UNIX, reglas
cerradas intactas y ninguna configuración activa retenida por procesos o el
observador. Se elimina sólo la entrada generada de runtime. Las concesiones
operacionales se conservan y no cambian durante la muestra deshabilitada. Los
dos slots vacíos mantienen sus inodos hasta retirar la encarnación completa;
no se afirma coste kernel ni cgroups cero.

Las fases registran BOOTTIME, CPU, RSS/PSS por PID y memoria del padre; éste
incluye harness e infraestructura compartida. Dos ventanas de cuatro segundos
permiten calcular deltas, sin atribuir todo el padre a Kea ni activar controllers.
Un contador obligatorio ausente hace fallar la prueba: cada muestra CPU exige
`usage_usec`, `user_usec` y `system_usec`; los campos adicionales son opcionales.
Sin hoja, las fases antes/después de infraestructura muestran `own_cpu:null`,
sin medición CPU de hoja. No son objetivos de sizing.

Ejecutar los controles de desarrollo sin privilegios y con fuente read-only:

```sh
go test -race ./internal/previewruntime -run '^TestRoutedDHCPServer' -count=1
go vet ./internal/previewruntime
go test -c ./internal/previewruntime -o /tmp/kea-lifecycle-native.test
bash -n packaging/preview/tests/dhcp-server-launch-lifecycle-native.sh
```

El skip nativo por defecto no constituye evidencia. Invocaciones por defecto,
en CI o sin root deben rechazarse antes de efectos. Sólo root ejecuta el ensayo
en Debian13 aislado autorizado, con snapshot/consola y unidad transitoria
exclusiva. Nunca Windows/WSL, appliance de cliente ni otra prueba simultánea.
Dependencias ya instaladas offline; servicio stock masked/inactive y AppArmor
intacto. Binario/script y ancestros deben estar protegidos por root.

El [procedimiento completo](dhcp-server-launch-lifecycle-native.en.md) define la
unidad transitoria, propiedades y placeholders explícitos de artefactos. Es un
bootstrap de laboratorio con root, no una prueba de privilegios de producción.
La unidad usa `LimitFSIZE=64M` sólo para copiar artefactos de hasta 64 MiB. Tras
las copias, chmod, creación de fixture y hashes, el driver elimina
`POSIXLY_CORRECT`, desactiva el modo POSIX de Bash y ejecuta
`ulimit -S -f 8192` y `ulimit -H -f 8192`. Bash usa bloques de 1024 bytes en ese
modo: fija 8.388.608 bytes. Antes de snapshots/unshare comprueba ambos límites y
la unidad `bytes` en `/proc/self/limits`; los hijos heredan el límite soft/hard
de 8 MiB, también si el entorno inicial tenía `POSIXLY_CORRECT=1`. No cambia
límites del producto.
Root captura InvocationID, salida y contabilidad antes de detener únicamente esa
invocación, comprobando FD store vacío y drenaje. No reset-failed ni borrado para
ocultar errores.

La evidencia permanece en `/var/backups/andeiva-kea-lifecycle.*`: JSON por fases,
observaciones, hashes e invariantes del host. Sólo se normalizan tiempos de vida
de direcciones/rutas, metadatos de versión nft y contadores de paquetes. La red
funcional, forwarding y mounts del host deben permanecer iguales. Ante fallo se
conserva evidencia; la unidad contenedora drena. No instala paquetes, desactiva
AppArmor, desmarca servicios, modifica la red del host ni borra evidencia.
