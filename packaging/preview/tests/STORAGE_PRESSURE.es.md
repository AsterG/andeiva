# Pruebas de almacenamiento finito

Ejecutar sólo en un laboratorio autorizado y recuperable Debian 13 AMD64. Se
necesitan root, `unshare`, herramientas de montaje y la cuenta existente `andeiva`
con UID/GID 1000. El harness crea un namespace de montaje y red privados y tres tmpfs
desechables de 16 MiB y 256 inodos. No cambia servicios, red, interfaces, rutas ni
reglas del appliance. Nunca llenar el filesystem del host para esta prueba.

Compilar el ejecutable en desarrollo desde el código revisado:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -trimpath -buildvcs=false -o configpoc-storage.test ./internal/configpoc
sha256sum configpoc-storage.test packaging/preview/tests/storage-pressure.sh
```

Transferir ambos archivos mediante un medio autorizado y verificar sus checksums
registrados por separado. Desde la consola, crear un directorio nuevo bajo un árbol protegido de root (por ejemplo `/root`) e instalar el ejecutable con modo 0555 y el harness con modo 0500.
Ejecutar con rutas absolutas y el SHA-256 verificado del ejecutable:

```sh
bash /RUTA/ABSOLUTA/ROOT/storage-pressure.sh --authorized-debian-lab /RUTA/ABSOLUTA/ROOT/configpoc-storage.test SHA256_VERIFICADO --isolated-storage-only
```

Resultado esperado: casos bytes, inodes y readonly aprobados, seguidos de
`ANDEIVA_STORAGE_LAB_RESULT=pass`. Bytes e inodos verifican admisión ordinaria,
lecturas y recuperación al retirar exclusivamente sus archivos de relleno.
Readonly comprueba el sondeo real de sólo lectura; no arranca un almacén ya
montado como sólo lectura. El harness desmonta sus tmpfs y retira el directorio
vacío. Si falla el desmontaje, no borrar la ruta recursivamente: inspeccionar el
namespace indicado y detener el proceso de prueba antes de limpiar.

Los motores son simulados; no se prueba tráfico. El resultado no demuestra cuotas,
reserva física, resistencia a cortes eléctricos, retención de auditoría protegida
ni continuidad permanente del dataplane. El espacio observado puede cambiar; los
fallos de escritura/fsync siguen requiriendo recuperación. Esos gates permanecen
abiertos. CI compartido sólo comprueba sintaxis, pruebas unitarias y compilación
multiplataforma; no ejecuta estas operaciones privilegiadas.
