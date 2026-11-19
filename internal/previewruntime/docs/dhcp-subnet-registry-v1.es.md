# IDs durables de subred DHCP

Registro operativo interno separado de configuración y leases; todavía no está
conectado al runtime. Bootstrap confiable entrega el FD del directorio protegido
y de su hijo fijo `leases`; la API no elige rutas. Raíz prevista:
`/var/lib/andeiva-preview-package/dhcp-server`, root:root 0700. El archivo
`scope-bindings.v1.json` exige root:root 0600. Leases exige 0700; bootstrap debe
comprobar además el propietario del motor mantenido.

La clave contiene scope ID, ID de interfaz LAN seleccionada, MAC física y subred
IPv4 canónica. Cambiar pools u opciones conserva el ID; cambiar interfaz, MAC o
subred asigna otro uint32 no nulo. La asignación crece sin reutilizar IDs y conserva
mapeos retirados, incluso al deshabilitar, rehabilitar o revertir configuración.
El orden del lote no cambia la asignación. Límites: 4096 entradas y 1 MiB.
El registro rechaza el ID 4294967295, reservado por Kea.

Un flock independiente del directorio serializa las llamadas. La publicación
sincroniza el marcador `scope-bindings.v1.pending` y el directorio antes de
preparar `scope-bindings.v1.publish`. La creación de ambos archivos es exclusiva
y evita seguir enlaces. Se sincroniza y renombra el candidato de forma atómica.
El marcador se retira sólo después de sincronizar el directorio tras el rename.
Si queda el marcador o el candidato, se bloquean todas las consultas. Si falla
la sincronización de la retirada del marcador, el intento devuelve error sin
IDs. El manifiesto ya está sincronizado, y si el marcador reaparece tras
reiniciar sigue bloqueando. El registro mantiene el servicio que ya estaba
activo. La E/S de disco puede demorar la cancelación.

El primer ID exige un directorio de leases vacío y bloqueado, incluso si ya
existe un manifiesto de cero entradas. Con el cupo lleno, las consultas
existentes siguen sin escrituras y fallan las nuevas asignaciones.

Para recuperar, detén el motor y todos los escritores durante mantenimiento
autorizado. Conserva juntos los archivos del registro y el directorio de leases
como evidencia del incidente. Verifica el almacenamiento, el historial completo
de asignaciones y que concuerde con los leases conservados. Sincroniza el
manifiesto verificado y su directorio antes de retirar el marcador o el
candidato. Vuelve a sincronizar el directorio después. Si falta evidencia,
mantén el bloqueo. Conserva todas las concesiones. El rollback de configuración
no debe restaurar el manifiesto por separado de su historial de leases.
Detectar una restauración arbitraria por root exige un ancla monotónica externa.

Linux/WSL, Go 1.27.4:

```sh
go test -race ./internal/previewruntime -run '^TestDHCPSubnetRegistryV1' -count=1
go vet ./internal/previewruntime
go build ./internal/previewruntime
go test -c -o /tmp/andeiva-dhcp-subnet-registry.test ./internal/previewruntime
```

Fixture de filesystem root opt-in: `ANDEIVA_NATIVE_DHCP_SUBNET_REGISTRY=1`, filtro
`^TestDHCPSubnetRegistryV1RootLifecycleNative$`. Sólo crea y retira su directorio
temporal; no inicia DHCP ni cambia red. No califica lifecycle, leases, cortes de
energía ni recursos productivos; faltan esas pruebas nativas/integradas. Revertir
código debe conservar registro y leases; no existe migración para degradar o
reutilizar IDs.
