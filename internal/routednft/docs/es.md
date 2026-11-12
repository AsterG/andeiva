# Laboratorio de firewall enrutado y SNAT

La prueba de tráfico nativo en Debian 13 y la revisión independiente pasaron.
No está conectado a Web/CLI/API, persistencia ni paquetes.

Sólo se admiten reglas explícitas IPv4 TCP/UDP ordenadas con CIDR, puertos,
interfaces y zonas del plan canónico. Se rechazan protocolos no soportados,
rutas de gestión, referencias inválidas, colisiones de marcas y requisitos de
identificación/inspección obligatoria: este experimento no implementa esos motores.
No hay excepción automática para tráfico desconocido. Masquerade sólo LAN→WAN
no concede autorización de forwarding.

Cada regla exige `enabled` explícito. Una regla inactiva conserva configuración
validada y hash, pero no genera reglas ni contadores del kernel. Se preservan los
IDs existentes de 1–64 caracteres alfanuméricos/punto/guion/guion bajo, con inicio
alfanumérico, sin renombrarlos. Las rutas IPv4 e IPv6 del host se comparan al salir.

La tabla exclusiva `inet andeiva_routed_alpha` conserva INPUT/OUTPUT intactos.
FORWARD prioridad 0 y política drop incluyen IPv6; NAT postrouting usa prioridad
100. Cada paquete vuelve a comprobar la regla vigente y el tuple original de
conntrack, incluso después de SNAT. Las respuestas requieren estado establecido
y marca propia de admisión; la marca no acredita identidad. RELATED sólo admite
errores ICMP destination-unreachable, time-exceeded y parameter-problem vinculados
al tuple, marca, interfaces y regla actuales. Echo/redirects y errores sin vínculo
no reciben excepción. La matriz negativa completa y PMTU siguen pendientes.

El adaptador serializa Check→Apply→lectura semántica completa, con lote atómico.
No confía sólo en comentarios/hash. Una confirmación perdida conserva únicamente
los estados anterior/destino autorizados. Los contadores se reinician al sustituir
la tabla; no son un inventario de conexiones ni logs de flujos.

Pruebas sin privilegios en Linux/WSL con Go 1.27.4 y caché offline:

```bash
go test -race ./internal/routednft ./cmd/andeiva-routing-lab
go test ./internal/routednft -run '^$' -fuzz FuzzReadback -fuzztime=10s -parallel=2
go vet ./internal/routednft ./cmd/andeiva-routing-lab
go test ./internal/routednft -run '^$' -bench . -benchmem
go build -trimpath -o /tmp/andeiva-routing-lab ./cmd/andeiva-routing-lab
/tmp/andeiva-routing-lab > /tmp/andeiva-routed-create.json
```

Tras revisión independiente, únicamente en VM Debian 13 amd64 desechable,
autorizada, con snapshot de recuperación, iproute2/nftables y binario confiable:

```bash
sudo /tmp/andeiva-routing-lab --run-isolated-lab
```

El runner crea tres namespaces aleatorios `andrt-...-{l,g,w}`, interfaces veth
dentro de ellos y forwarding sólo en gateway aislado. Revalida inode del namespace
y nombre/MAC/índice mediante `networkinventory.Discover` + `networkplan.Bind`.
No usa shell; ejecutables, salida y plazos están acotados. Compara rutas y
nftables del host antes/después mediante observaciones de sólo lectura.

Verifica SNAT TCP/UDP por dirección observada en servidor, ICMP relacionado con
contador exacto, IPv6 bloqueado con contador, entrada inversa no solicitada con
servidor/ruta presentes, revocación TCP ya establecida, ruta sin NAT y NAT sin
permiso de forwarding. Error implica salida no cero. No ejecutar en equipos
de clientes ni modificar las redes del host Windows.

La reversión elimina únicamente namespaces creados por esta invocación y con
inode coincidente después de parar sus hijos. Funciona ante éxito, error,
timeout, SIGINT y SIGTERM. SIGKILL/fallo físico o sustitución del namespace pueden
dejar objetos: verificar propiedad manualmente con los nombres impresos; nunca
borrar por prefijo solamente. No se modifican rutas/NAT/SSH del host.

Pruebas reales: TCP/UDP con SNAT observado por el servidor, ICMP relacionado, bloqueo IPv6 con contador, tráfico inverso no solicitado denegado, conexión TCP existente revocada, routing sin NAT y NAT sin autorización de forwarding. Limpieza e invariantes externos de rutas IPv4/IPv6 y nftables aprobados. Proceso de prueba: 3,635 s transcurridos, 0,312 s CPU y pico cgroup 30.273.536 bytes, incluidos hijos/caché; no es RSS de servicio ni medición de throughput.

Se corrigieron incompatibilidades de contexto ICMP, conjuntos de tipos ICMP y selectores conntrack IPv4. La lectura conserva direcciones, prefijos, puertos, marcas y acciones. Siguen pendientes integración transaccional, paridad administrativa, inventario de sesiones traducidas y pruebas sostenidas/PMTU. No es un firewall de producción.
