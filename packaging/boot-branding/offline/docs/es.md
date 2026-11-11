# Bundle experimental de arranque sin conexión

Sólo para desarrollo interno autorizado. No es una actualización firmada, una release, un instalador A/B ni una autorización para redistribuir las dependencias. El checksum detecta cambios; obtén el bundle y su checksum esperado por un canal confiable independiente. Nunca ejecutes como root un instalador no confiable.

## Construcción

Utiliza un entorno de desarrollo Debian 13 AMD64 sin root, con APT, el llavero Debian, sqv, dpkg, Go según `go.mod`, GNU tar/coreutils, gzip y util-linux. Sólo esta etapa consulta los repositorios oficiales Debian fijados. Se conservan las verificaciones de firma, fecha, caducidad y HTTPS.

```sh
bash packaging/boot-branding/offline/build.sh \
  /private/target-dpkg-status /private/reviewed-product-debs \
  /private/bundle-output 1794355200
```

El directorio de producto debe contener exactamente `andeiva-boot-branding` y `andeiva-boot-activation`, revisados y con la misma versión experimental. El activador debe declarar la protección de instalación offline versión 1. El estado dpkg privado influye en la resolución, pero no se incluye. Consérvalo de forma privada para repetir la construcción. La reproducibilidad byte a byte requiere los mismos paquetes y metadatos firmados; los repositorios pueden cambiar entre ejecuciones.

Antes de resolver o instalar, deben estar configurados `grub-common`, `grub2-common`, `grub-pc` y `grub-pc-bin` versión `2.12-9+deb13u2` (amd64), además de `initramfs-tools` e `initramfs-tools-core` versión `0.148.4` (all). Este bundle no puede instalarlos ni actualizarlos. Sólo admite subconjuntos de 26 tuplas de dependencias revisadas y compiladas; una firma válida no autoriza una versión/hash diferente. Las actualizaciones de seguridad requieren su procedimiento calificado; no eludas este control ni lo interpretes como congelación indefinida.

## Inspección e instalación

El alcance actual admite Debian 13 AMD64, BIOS y una raíz ext4 que contenga `/boot`, `/etc`, `/usr` y `/var/backups`, sin arquitecturas dpkg adicionales. Se rechazan otros diseños. Esto no certifica todos los equipos o hipervisores. Antes de instalar exige espacio suficiente, dpkg sano, dos kernels completos y recuperación independiente ensayada. No instala kernels ni convierte Debian existente en A/B.

Comprueba el checksum esperado antes de extraer. Extrae únicamente un bundle confiable a un directorio controlado y revísalo antes de colocarlo, como root y sin escritura para otros, en `/var/lib/andeiva-boot-bundles/INVENTORY_SHA256`. La construcción muestra ese identificador. No añadas estados privados, credenciales ni evidencias de diagnóstico.

```sh
cd /var/lib/andeiva-boot-bundles/INVENTORY_SHA256
./install.sh inspect
./install.sh install --recovery-verified
```

`inspect` verifica firmas, hashes, inventario y simulación APT sin conexión; elimina su staging temporal. `install` repite la validación, exige reconocer la recuperación y respalda arranque/configuración antes de APT en un namespace de montaje privado. Sólo ese namespace recibe `update_initramfs=no` mediante bind de sólo lectura. No carga fuentes, preferencias ni hooks APT del host. No ejecuta APT online, actualizaciones, eliminaciones, activación del tema ni reinicio. Las versiones instaladas deben coincidir. Un activador existente debe informar `offline_install_guard: 1`; uno anterior necesita una actualización revisada por separado.

Tras el éxito se verifican versiones, capacidad de protección, hashes de arranque, inventario de kernels y política initramfs original antes de retirar el marcador persistente. Repetir la instalación completada devuelve `ANDEIVA_OFFLINE_ALREADY_INSTALLED`. Activar el branding sigue siendo otra operación con sus propias garantías de recuperación.

El identificador vincula todos los archivos, incluidos instalador y verificador: es SHA-256 del archivo canónico `SHA256SUMS`. No se aceptan los identificadores antiguos basados sólo en paquetes. Los logs combinan stdout/stderr, ocupan como máximo 4 MiB e indican explícitamente el truncamiento. Se continúa leyendo la salida restante incluso tras fallar la escritura. El timeout abarca productor y logger, incluidos hijos que mantienen el pipe abierto. Un truncamiento, error de escritura o fallo de cualquiera de los procesos conserva el estado pendiente aunque APT haya instalado todo correctamente.

Únicamente el log terminal duplicado de APT se redirige a `/dev/null`; se conservan el log principal acotado, el historial APT y la auditoría de acciones dpkg. Otros logs del sistema, historial/planner y scripts de paquetes no quedan cubiertos automáticamente por 4 MiB: necesitan política de almacenamiento y validación nativa. Las copias de caché usan nombres canónicos APT y hash verificado, incluido `%3a` minúsculo para epochs, sin habilitar descargas.

## Fallos y recuperación

Una interrupción posterior a la creación del marcador conserva `/var/backups/andeiva-boot-offline/install-pending` y los respaldos privados. La instalación y la activación deben rechazar ese estado incierto aunque todos los paquetes parezcan instalados. Un hijo APT puede sobrevivir al instalador; que no exista el proceso padre no demuestra que terminó.

Este incremento no proporciona rollback de paquetes, reanudación ni comando para borrar el marcador. No lo elimines ni ejecutes reparación APT genérica para eludirlo. La recuperación autorizada debe comprobar que APT/dpkg y sus hijos finalizaron, verificar respaldos y estado real de arranque/configuración/paquetes, y utilizar un procedimiento revisado o el snapshot/backup independiente ya ensayado. Mantén las evidencias privadas. Desinstalar el producto o borrar el marcador no revierte scripts Debian.

## Límites de validación

```sh
go test -race ./packaging/boot-branding/offline/check
go vet ./packaging/boot-branding/offline/check
bash -n packaging/boot-branding/offline/*.sh
```

Fixtures y sintaxis no demuestran aislamiento real, recuperación tras interrupción, instalación limpia ni consumo nativo. Requieren evidencia y revisión independiente. El bundle no agrega procesos permanentes; CPU, memoria, tiempo y disco de instalación siguen pendientes de medición en destino.

El ancla de confianza Debian existente debe ser el archivo regular `/usr/share/keyrings/debian-archive-keyring.pgp`, propiedad de root y sin escritura para grupo u otros, con directorios ascendentes seguros. No se utiliza el alias simbólico convencional `.gpg` ni se aceptan otras rutas o enlaces de llaveros.
