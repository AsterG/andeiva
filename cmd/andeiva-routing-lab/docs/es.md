# Cualificación del plan de red tipado

## Modo Group pendiente de cualificación nativa

`--run-isolated-group-lab-with-flows` reutiliza estos tres namespaces y el ancla
host revisada. Pasan las pruebas de fuente/unitarias; ejecutar Debian requiere
revisión y autorización del propietario. Usa Engine/Group reales de
routedactivation, snapshot exacto, transporte nft de tablas fijas y resolver de
artefactos efímero explícitamente confiable. Es un registro de fixture, no un
coordinador durable de producción.

Comienza con schema 4 realmente instalado y sus dos reglas guardadas. Comprueba
TCP/UDP SNAT pendiente y recuperación fría exacta; después crea otra
operación del fixture y confirma una lease distinta de treinta segundos. Todos
los cambios posteriores pasan por Group y conservan las pruebas NAT/conntrack/
deny/revocación. Restaura schema 4 exacto, lo confirma y vuelve a activar schema 6.
La última inversión 6→4 vence en su deadline original de treinta segundos y debe
reponer red/reglas schema-6 previas reales. Sólo una consulta completa exitosa
demuestra ausencia. Provisionar el baseline del fixture no cualifica publicación
Boot/SystemBundle de producción; PrepareColdBoot se comprueba por separado.

El perfil local no inicia procesos/listeners de servicios en gateway y comprueba
sus tablas TCP/UDP reales. Nunca enumera ni detiene SSH/HTTPS del host. Un vecino
IPv6 permanente en el peer LAN propio permite llegar al drop de forward sin
agregar reglas allow. Forwarding se habilita después de instalar deny/target real.

Marcadores adicionales, exclusivamente tras comprobaciones exitosas:

```text
PASS typed group initial schema4 has exact two saved rules
PASS typed group TCP/UDP SNAT and exact cold recovery
PASS typed group distinct confirmed lease and exact lost-confirm reconciliation
PASS typed group saved schema4 restores exact two-rule legacy and empty network
PASS typed group confirmed schema4 reactivates owned schema6
PASS typed group inverse saved schema4 deadline expired and exact schema6 recovered
```

Group tiene límite de 80 segundos y limpieza independiente acotada; el modo previo
sin Group conserva 55 segundos. No cambian deadlines del producto. La fuente
`3918ad8` pasó el escenario Group anterior nativo en 46.166222 s (CPU 13.259767 s,
pico 31,281,152 bytes); esa evidencia no cualifica este nuevo runner inverse/dos reglas.
No cualifica reinicio del helper, migración LAN existente, continuidad de endpoints
ni recuperación durable de producción. RecoverPrepared tiene pruebas unitarias
separadas y exige WorkScope original autenticado y la misma encarnación retenida;
NewWithHost no concede capacidad de reconstrucción.

```sh
go test -race ./cmd/andeiva-routing-lab ./internal/routedactivation ./internal/nftguardian ./internal/networkexecutor -count=3
```

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
