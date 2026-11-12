# Reserva física de recuperación

Primitiva interna con 1–32 archivos fijos y dos bancos alineados, preasignados y
con checksum. Cada banco admite entre 4 KiB y 1 MiB. Requiere `fallocate` Linux;
rechaza alternativas dispersas y verifica propietario, permisos, dispositivo,
inodo y bloqueo exclusivo del directorio privado recibido como descriptor.

`Claim` asigna espacio a una operación. `Write` comprueba la concesión, escribe
el banco inactivo y sincroniza datos y cabecera. Los resultados inciertos
bloquean nuevas escrituras del handle. No crea archivos durante estas operaciones
ni recicla reservas por antigüedad. No modifica configuración, auditoría o red.

El coordinador deberá guardar el `Binding` exacto junto a su intención durable.
Sólo `ReadBound` acredita pool, posición, propietario, secuencia y digest.
`Read(owner)` puede recuperar un banco anterior; no acredita una transacción
completada. Un primer Claim dañado no libera su espacio. Los checksums detectan
corrupción; no son firmas ni protegen frente al propietario malicioso del disco.

## Reproducción

```sh
go test -race ./internal/recoveryreserve -count=3
go vet ./internal/recoveryreserve
GOOS=linux GOARCH=amd64 go test -c ./internal/recoveryreserve -o reserve.test
sha256sum reserve.test
```

En Debian 13 de laboratorio, con consola y snapshot recuperable, copie el binario
y repositorio. Instale el binario en un directorio privado propiedad de root y
ejecute como root:

```sh
bash packaging/preview/tests/recovery-reserve-pressure.sh \
  --qualify-isolated-ext4 /ruta/absoluta/root/reserve.test SHA256 andeiva
```

Sustituya SHA256 por el digest hexadecimal verificado y `andeiva` por una cuenta
no privilegiada existente cuyo grupo principal tenga el mismo nombre. El script
usa namespaces privados de montaje/red y una nueva imagen ext4 de 64 MiB. Prueba
agotamiento de bloques e inodos y lectura exacta tras reabrir; desmonta la imagen
y conserva el directorio de evidencia. No se ejecuta con privilegios en CI.

No activa almacenamiento del appliance. Faltan integración del coordinador,
aislamiento por cuotas, RO/EIO/EDQUOT, retiro autorizado y continuidad de tráfico.
La preasignación y las pruebas ext4 no garantizan metadatos/journal/COW en todos
los dispositivos. Las interrupciones de proceso no prueban cortes eléctricos.
Las pruebas Debian13 pasaron agotamiento real de bloques e inodos en ext4 aislado64MiB, UID1000 sin capacidades. Lectura Binding/reapertura0,62s; CPU de preparación/prueba0,414153s/pico cgroup74.477.568B incluyen formateador y caché. Regresión nativa separada: CPU0,049284s/pico16.248.832B. Son mediciones del fixture; no RSS del servicio, garantía universal ni continuidad integral del appliance.
