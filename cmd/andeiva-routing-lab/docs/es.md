# Cualificación del plan de red tipado

El laboratorio Debian 13 existente de tres namespaces aplica las dos direcciones
IPv4 estáticas y la ruta predeterminada del gateway mediante
`internal/networkexecutor`. Verifica el namespace propio, abre y comprueba el
inodo del montaje, y entrega un descriptor confiable y una vida de recuperación
del supervisor independiente. Veth, MAC, estado de enlaces, rutas de los pares e
IPv6 siguen siendo preparación del fixture. Conserva pruebas TCP/UDP, SNAT,
denegación, revocación, IPv6 y conntrack observado opcional. Sin namespaces nuevos.

`Apply` y `Verify` deben pasar antes del tráfico. Al salir: detener procesos hijos,
`Restore` con verificación del snapshot IPv4 controlado, `Close` y finalmente
eliminar namespaces propios. La restauración conserva la vida del supervisor
aunque expire la solicitud del laboratorio. Los fallos de limpieza hacen fallar
la ejecución.

Marcadores emitidos sólo tras completar correctamente cada operación:

```text
PASS typed network plan applied/readback
PASS typed network plan applied/readback/restored
PASS namespaces cleaned; host routes and nftables unchanged
```

Integración preparada para revisión, sin cualificación privilegiada acreditada.
Pruebas sin privilegios:

```sh
go test -race ./internal/networkexecutor ./cmd/andeiva-routing-lab ./internal/routednft
go vet ./internal/networkexecutor ./cmd/andeiva-routing-lab
go build -trimpath -o /tmp/andeiva-routing-lab ./cmd/andeiva-routing-lab
```

Sólo tras revisión de código y autorización explícita del laboratorio aislado,
en VM Debian 13 amd64 desechable con snapshot de recuperación y herramientas
necesarias ya instaladas:

```sh
sudo /tmp/andeiva-routing-lab --run-isolated-lab-with-flows
```

Nunca ejecutar en un appliance de cliente ni modificar redes Windows/VPN.
Requiere IPv4 inicialmente vacío; no admite migración de LAN administrativa,
DHCP o recuperación durable. El estado de recuperación permanece en memoria.
No modifica routing, NAT, firewall o sysctls del host. No acredita producción,
inspección obligatoria, integración Docker/EKS ni cierre de Firewall & Routing
Alpha. Mediciones CPU/RAM pendientes.
