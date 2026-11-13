# Configuración del servidor DHCPv4

Estado: contrato y validación; no hay servidor, listener, base de concesiones,
API administrativa ni integración de ejecución. El cliente DHCP WAN es distinto.

El esquema 1 permite habilitación y hasta 32 ámbitos vinculados a interfaces LAN
del inventario confiable y su configuración de red seleccionada. Cada ámbito
declara subred, dirección del appliance, hasta 32 rangos no superpuestos, 256
exclusiones y 256 reservas MAC. Las reservas quedan fuera de la asignación general,
incluso si pertenecen a un rango. Una reserva excluida se rechaza. La capacidad
total declarada se limita a 65.536 direcciones antes de exclusiones.

Opciones: puerta de enlace, hasta cuatro DNS y cuatro NTP, dominio ASCII canónico,
duración de concesión entre 60 segundos y siete días, renovación y revinculación
ordenadas antes del vencimiento. No incluye todavía identificadores de cliente,
relay, DHCPv6, opciones arbitrarias, DNS dinámico ni HA.

Se rechazan interfaces ambiguas o WAN, subredes/rangos superpuestos, direcciones
de red/broadcast y router dentro del rango sin exclusión. La decodificación es
acotada y rechaza campos desconocidos, duplicados o con alias de mayúsculas.
Deshabilitar conserva la configuración validada, pero la integración futura debe
retirar todos sus recursos exclusivos.

Antes de activar: revisión del motor/licencias/dependencias offline, transacciones
con confirmación/guardado/rollback, RBAC/auditoría y paridad Web/CLI/API; protección
Local-In independiente de forwarding/NAT; detección de servidores en conflicto y
pruebas reales de concesiones, reservas, agotamiento, reinicios y presión de disco.
Una validación satisfactoria no demuestra esas capacidades ni autoriza tráfico.

Debian minimal no debe suponerse equipado con servidor DHCP. El bundle offline
debe contener el motor elegido y todas sus dependencias compatibles, procedencia
verificada, checksums, SBOM y licencias. No habrá descargas ni `apt` al activar la
función. Kea es candidato; su paquete `kea-dhcp4-server` depende de `kea-common`
de la misma versión y otras bibliotecas. No se instala todavía desde este código.

La instalación debe impedir que los scripts del paquete arranquen un servidor
competidor antes de la habilitación explícita, conservando la política de servicios
existente. No sobrescribir `policy-rc.d` ni desactivar servicios ajenos. Probar
instalación limpia/offline, dependencia ausente o corrupta, servicio preexistente,
actualización, interrupción, rollback y desinstalación sin eliminar paquetes ajenos.

```sh
go test -race ./internal/dhcpserver
go vet ./internal/dhcpserver
go build ./internal/dhcpserver
```
