# Volúmenes inactivos de almacenamiento para laboratorio

Este componente de desarrollo prepara cuatro imágenes ext4 **inactivas**. No
monta, activa, migra ni elimina datos; no añade servicios, listeners ni tareas
periódicas. No cierra AND-01/AND-02 ni demuestra continuidad del tráfico con el
almacenamiento lleno. `andeiva` sigue siendo la CLI administrativa oficial;
`andeiva-storage-lab` es una herramienta local de desarrollo exclusiva de root.

## Perfil fijo de pruebas

| Dominio | Capacidad de imagen | Inodos solicitados |
| --- | ---: | ---: |
| Configuración | 128 MiB | 8192 |
| Auditoría protegida | 128 MiB | 4096 |
| Observaciones | 64 MiB | 1024 |
| Recuperación | 64 MiB | 2048 |

Total: 384 MiB. Metadatos y journals consumen parte de cada imagen; no son bytes
libres utilizables ni un dimensionamiento de producto aprobado. Se exige además
espacio observado de 64 MiB y 64 inodos en el sistema de archivos contenedor.
Es admisión, no una cuota ni protección ante escrituras externas concurrentes.

Se exige asignación de bloques mediante fallocate, sin alternativa sparse ni
truncate. El formateador recibe únicamente el descriptor heredado 3 del archivo
regular nuevo, creado de forma exclusiva; nunca una ruta o dispositivo del
operador. Se ejecuta `/usr/sbin/mke2fs` con argumentos y entorno fijos, un solo
`-F` y `nodiscard,lazy_itable_init=0,lazy_journal_init=0`. Se verifican propietario,
permisos y ancestros; la procedencia del paquete debe validarla el operador.
Después del formato se preserva cada byte mediante lectura/escritura acotada,
se sincroniza y se comprueban identidad, tamaño, enlaces, bloques, firma y SHA-256.
El manifiesto se publica atómicamente sin reemplazar destinos existentes.

La asignación corresponde a lo visible para el ext4 contenedor. No acredita
capacidad física bajo thin provisioning, snapshots o fallos del medio. Tampoco
protege frente a root malicioso ni demuestra resistencia a cortes eléctricos.
Los montajes privados y el enlace con servicios reales siguen siendo pruebas
independientes. Véase el [manual de mke2fs](https://man7.org/linux/man-pages/man8/mke2fs.8.html).

## Compilación y ejecución

Con la versión Go fijada por el repositorio, sin root:

```sh
go test -race ./internal/storagevol ./cmd/andeiva-storage-lab
go vet ./internal/storagevol ./cmd/andeiva-storage-lab
go build -trimpath -buildvcs=false -o /tmp/andeiva-storage-lab ./cmd/andeiva-storage-lab
sha256sum /tmp/andeiva-storage-lab
```

Transferir solo el binario revisado y contrastar su checksum conservado por una
vía confiable independiente. La preparación nativa exige UID/GID root 0, Debian
13 AMD64 y un sistema contenedor ext4. No instala paquetes ni cambia flags del
sistema de archivos. El indicador expresa intención del operador, no autentica
ni demuestra propiedad del laboratorio. Con laboratorio autorizado y recuperable:

```sh
andeiva-storage-lab --authorized-debian-lab --operation plan
andeiva-storage-lab --authorized-debian-lab --operation prepare
andeiva-storage-lab --authorized-debian-lab --operation inspect --id PREPARED_ID
```

`PREPARED_ID` es el identificador hexadecimal de 32 caracteres minúsculos devuelto
por `prepare`. La base fija es `/var/lib/andeiva-storage-lab`; no acepta rutas ni
tamaños alternativos. Una preparación existente, incluso incompleta, bloquea otra.
Se rechazan archivos desconocidos, enlaces, permisos o propietarios incorrectos
y manifiestos inválidos sin borrarlos. Ayuda: `--lang es --help`.

Un fallo conserva el área parcial. Una publicación incierta devuelve
`ANDEIVA_STORAGE_VOLUME_UNCERTAIN`. La inspección de solo lectura puede verificar
una preparación completa tras interrumpir el proceso; no vuelve a baselinar
imágenes modificadas por montajes o escrituras posteriores.

## Pruebas nativas y limpieza

El coordinador utiliza el harness existente
`packaging/preview/tests/storage-pressure.sh`, con namespaces privados de montaje
y red. No montar imágenes en runners compartidos ni duplicar el harness.
Falta demostrar identidades y presupuestos independientes, llenar observaciones
por bytes/inodos y mantener intacto el espacio de configuración/recuperación.
ENOSPC, EROFS, EDQUOT y continuidad del dataplane son gates separados.

No existe comando de borrado. Antes de una limpieza explícita del conjunto de
prueba propio e inactivo, el operador autorizado debe verificar que todas las
imágenes estén desmontadas y desvinculadas, y conservar evidencia. No borrar
recursivamente rutas arbitrarias ni aplicar esto a configuración o auditoría viva.
El appliance, sus interfaces, rutas, arranque y servicios permanecen intactos.

Las pruebas unitarias usan asignación real de archivos y una **firma simulada de
formateador**, no imágenes ext4 montables. Cubren colisiones de publicación,
interrupciones y salidas reales de procesos, sustituciones, enlaces/FIFO,
permisos, manifiestos inválidos y conservación de archivos ajenos. Formato real,
montajes y recursos nativos siguen pendientes hasta documentar su ejecución.
El benchmark usa una fixture de firma de 16 MiB, no capacidad sostenida ni formato
nativo:

```sh
go test ./internal/storagevol -run '^$' -bench '^BenchmarkInactivePreparation$' -benchtime=3x -benchmem
```
## Selección y amenazas

Las cuotas de proyecto pueden limitar directorios, pero dependen del soporte y
la contabilidad correcta del filesystem existente; no crean reservas de inodos
independientes ni impiden escrituras ajenas de root. Esta prueba prepara archivos
de tamaño fijo para filesystems ext4 separados, con presupuestos de bytes e
inodos independientes cuando los monte el harness autorizado. No reparticiona ni
remonta la raíz. El diseño productivo requiere ubicación de volúmenes, reservas,
retención de auditoría protegida y pruebas del almacenamiento inferior.
Se verifican rutas ajenas, enlaces, preparación concurrente, archivos parciales y
publicación incierta; un root malicioso queda fuera del modelo.

## Prueba nativa opcional con copias

El mismo harness admite un modo opt-in adicional; el modo tmpfs de cuatro
argumentos permanece intacto. Compilar sin root:

```sh
CGO_ENABLED=0 go test -c -o /tmp/storagevol.test ./internal/storagevol
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /tmp/andeiva-storage-lab ./cmd/andeiva-storage-lab
sha256sum /tmp/storagevol.test /tmp/andeiva-storage-lab
```

Transferir binarios y harness revisados a un directorio de root con ancestros no
escribibles por otros, verificando hashes. En Debian autorizado, como root:

```sh
bash /root/storage-pressure.sh --authorized-debian-volumes \
  /root/storagevol.test RUNNER_SHA256 --isolated-storage-only \
  /root/andeiva-storage-lab INSPECTOR_SHA256 PREPARED_ID
```

Sustituir los marcadores por valores verificados. `harness-plan` es una salida de
solo lectura con campos fijos de `inspect`, sin rutas arbitrarias. El harness
verifica originales y copia 384 MiB sin reflinks ni archivos sparse. Solo monta
copias en namespaces privados de montaje/red. Exige 512 MiB libres antes de
copiar; originales y copias ocupan 768 MiB más ejecutables/metadatos pequeños.
La base fija es `/var/lib/andeiva-storage-pressure`; residuos bloquean otro ciclo.

Comprueba ENOSPC por bytes e inodos, EROFS y liberación de un archivo eliminado
que sigue abierto hasta cerrarlo. Los bloques/inodos libres de configuración,
auditoría y recuperación deben permanecer iguales durante cada presión;
configuración y recuperación deben aceptar escritura/fsync. No demuestra
continuidad del appliance. Desmonta y separa loops antes de borrar solo copias
propias; si falla la limpieza conserva el workspace para recuperación autorizada.
No fuerza desmontajes ni elimina originales o auditoría protegida. El resultado
Debian debe registrarse aparte; las pruebas normales/CI omiten este test y no
realizan montajes.

El harness rechaza runners/inspectores mayores de 32 MiB y scripts mayores de
128 KiB antes de calcular hashes/copiar. Captura logs acotados exclusivos de root
y exige RUN/PASS reales; los casos nativos requieren además un marcador exacto
al terminar todas las comprobaciones. Exit0 sin tests es fallo. Si falla un test,
conserva copias separadas de sus loops y logs para recuperación autorizada y
bloquea otro ciclo. En éxito retira sus copias y logs. Regresión sin root/montajes:

```sh
bash packaging/preview/tests/storage-pressure-log-test.sh
```
