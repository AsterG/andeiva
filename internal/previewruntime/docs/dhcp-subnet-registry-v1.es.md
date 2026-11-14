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

Flock independiente del directorio serializa llamadas. Creación exclusiva sin
seguir enlaces, fsync del archivo, rename atómico y fsync del directorio preceden
a devolver IDs. Cualquier fallo de persistencia devuelve cero IDs: no iniciar
el motor. Un archivo pendiente bloquea por incertidumbre; no se adopta ni borra
automáticamente. La cancelación es cooperativa, sin garantía temporal sobre disco.
El registro nunca detiene el servicio existente.

Sin registro, cualquier lease existente impide inicializar. Sólo un directorio
de leases vacío y bloqueado permite hacerlo. Con el cupo lleno, las claves
existentes se consultan sin escribir; nuevas asignaciones fallan. Escrituras
parciales inciertas bloquean resolución hasta recuperación protegida. No hay
reparación automática. Restauraciones o borrados arbitrarios de root no se pueden
detectar sin un ancla monotónica externa; rollback de configuración nunca debe
restaurar este registro independientemente de su historia de leases.

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
