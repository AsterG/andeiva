# DHCP socket observations

## English

Read-only Linux inet_diag capture for unconnected IPv4 UDP sockets. Returns kernel cookie, inode, UID, bound interface and creation-cgroup metadata. It does not identify the current descriptor holder, authorize DHCP or change firewall/network state. Wildcard and unbound endpoints remain visible; callers must reject unsupported resources explicitly. CapturePacket provides a separate AF_PACKET inventory (interface, socket type, protocol, UID, cookie and inode). Linux packet_diag supplies no creation-cgroup attribute; this inventory does not attribute packet sockets to a service. TCP, connected UDP and IPv6 require separate inventory.

A dump must have a kernel sender, matching sequence/port, successful completion and unique nonzero identities. Missing attributes, interruption, truncation, malformed lengths, duplicate identities, cancellation or limits fail the entire capture. Bounds: 64 sockets, 64KiB datagram, 128 receive iterations and at most one second (or the caller's earlier deadline). No worker, timer or file exists when unused.

Run from repository root on Linux: `go test -race ./internal/dhcpsockets`, `go vet ./internal/dhcpsockets`. The integration test compares a real loopback UDP socket with its kernel cookie/inode/UID; it requires no network capabilities. This component is not yet wired to appliance policy and does not establish functional WAN qualification.

## Español

Captura Linux de sólo lectura para sockets UDP IPv4 no conectados. Devuelve cookie, inode, UID, interfaz vinculada y cgroup de creación del kernel; no demuestra el poseedor actual del descriptor ni autoriza DHCP. Conserva endpoints wildcard/no vinculados para que el consumidor los evalúe. CapturePacket añade inventario AF_PACKET (interfaz, tipo, protocolo, UID, cookie e inode), sin atributo de cgroup ni atribución a servicio. TCP, UDP conectado e IPv6 necesitan inventario independiente.

Errores, captura incompleta, identidades duplicadas o vencimiento rechazan el resultado completo. Límites:64 sockets, datagrama64KiB,128 iteraciones y como máximo1s. No crea procesos persistentes ni modifica redes. Las pruebas anteriores verifican un socket loopback real; la integración WAN permanece pendiente.

## Português

Captura Linux somente leitura para sockets UDP IPv4 não conectados. Retorna cookie, inode, UID, interface vinculada e cgroup de criação do kernel; não comprova o detentor atual do descritor nem autoriza DHCP. Preserva endpoints wildcard/não vinculados para avaliação do consumidor. CapturePacket adiciona inventário AF_PACKET (interface, tipo, protocolo, UID, cookie e inode), sem atributo de cgroup nem atribuição a serviço. TCP, UDP conectado e IPv6 exigem inventário separado.

Erros, captura incompleta, identidades duplicadas ou prazo vencido rejeitam todo o resultado. Limites:64 sockets, datagrama64KiB,128 iterações e no máximo1s. Não cria processos persistentes nem altera redes. Os comandos acima verificam um socket loopback real; a integração WAN permanece pendente.

Wire layout references: [Linux6.12 packet_diag UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/packet_diag.h), [kernel packet_diag implementation](https://github.com/torvalds/linux/blob/v6.12/net/packet/diag.c). Unbound, all-protocol and unexpected-interface packet sockets remain visible for evaluation against the declared service profile; RAW/ETH_P_ALL can be a legitimate maintained DHCP resource on its bound WAN. Native positive AF_PACKET socket creation is not covered by ordinary unprivileged tests.
