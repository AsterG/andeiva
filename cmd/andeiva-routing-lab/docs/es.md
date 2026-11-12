# Cualificación del plan de red tipado

El laboratorio Debian 13 existente de tres namespaces aplica las dos direcciones
IPv4 estáticas y la ruta predeterminada del gateway mediante
`internal/networkexecutor`. Verifica el namespace propio, abre y comprueba el
inodo del montaje, y entrega un descriptor confiable y una vida de recuperación
del supervisor independiente. Veth, MAC, estado de enlaces, rutas de los pares e
IPv6 siguen siendo preparación del fixture. Conserva pruebas TCP/UDP, SNAT,
denegación, revocación, IPv6 y conntrack observado opcional. Sin namespaces nuevos.

La unidad del laboratorio propiedad de root con capacidades mínimas admite sólo
el opt-in literal `ANDEIVA_LAB_HOST_ANCHOR_FD=0`. El gestor entrega FD 0 mediante
`StandardInput=file:/proc/1/ns/net` antes de reducir privilegios; el runner utiliza
`NewWithHost` con `os.Stdin`. Rechaza otros números o rutas. Sin opt-in conserva
`New` y el control de PID 1. No agrega SYS_PTRACE ni acepta identidades de host
del llamador ni debilita controles. Los errores identifican constructor, apply o
verify con etapas del laboratorio en inglés.

Fragmento probado para un harness del laboratorio propiedad de root y revisado,
no una unidad completa; el supervisor conserva el namespace de red del host:

```ini
[Service]
StandardInput=file:/proc/1/ns/net
Environment=ANDEIVA_LAB_HOST_ANCHOR_FD=0
```

El modo de flujos requiere `nf_conntrack_netlink` cargado antes de iniciar.
Comprobar `test -d /sys/module/nf_conntrack_netlink`. Si falta, sólo el supervisor
root explícitamente autorizado puede ejecutar `sudo modprobe nf_conntrack_netlink`
como requisito de laboratorio. El helper no carga módulos ni recibe SYS_MODULE;
no agregar SYS_PTRACE para acceder a PID 1. El runner no instala paquetes.

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

Fuente `460fece`, prefijo SHA-256 del binario `590a4005`: cualificación nativa
Debian 13 amd64 PASS con sólo SYS_ADMIN/NET_ADMIN y FD 0 de host suministrado.
Pasaron plan tipado, TCP/UDP SNAT, conntrack real, ICMP relacionado, denegación
IPv6/reversa, revocación TCP, routing sin NAT, límite de autorización de NAT,
limpieza e invariantes externos del host. Revisiones de root y arquitectura sin
hallazgos críticos/altos/moderados. Tiempo 4.408428 s, CPU 1.116154 s, pico
32,321,536 bytes: una ejecución del fixture, no benchmark del appliance.

Antes de reproducir, pruebas sin privilegios:

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
Alpha. Contenedores y presupuesto de recursos del appliance sin cualificar.
