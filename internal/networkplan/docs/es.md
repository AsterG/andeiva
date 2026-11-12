# Modelo de red enrutada

Preparación interna e inactiva: valida IPv4 WAN DHCP/estática, LAN/administración
estática, zonas, una ruta predeterminada WAN y DNS. No cambia interfaces, rutas,
forwarding, servicios ni reglas. No hay puente, VLAN, PPPoE, NAT ni servidor DHCP.

Decode limita el documento a 64 KiB y rechaza campos duplicados, desconocidos,
alias de mayúsculas/Unicode y valores posteriores. Canonical conserva los bits
de host y genera una revisión determinista. Se limitan colecciones y campos.

La asociación persistente usa nombre y MAC; el índice se resuelve desde inventario
confiable actual y puede cambiar al reiniciar. Una IP observada no prueba una
concesión DHCP. Los hashes no autentican ni prueban conectividad o IP libre.
IPv6 forwarding deny expresa un requisito pendiente de aplicación, no reglas reales.

El futuro ejecutor necesita helper autenticado, RBAC, auditoría, transacciones y
comprobaciones previas/posteriores. Debe preservar acceso administrativo anterior
hasta confirmar recuperación segura. Esta validación no autoriza cambios del host.

Pruebas reproducibles:

```sh
go test -race ./internal/networkplan ./internal/jsoncheck ./internal/nftengine
go vet ./internal/networkplan ./internal/jsoncheck ./internal/nftengine
```

Se prueban revisiones, CIDR, conflictos, DNS/gateway, identidad, cambios legítimos
de índice, ambigüedad DHCP y JSON. No prueban routing/NAT. Integración y consumo
real Debian pendientes. Reversión: retirar código inactivo; no deja recursos runtime.
