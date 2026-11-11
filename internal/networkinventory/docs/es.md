# Inventario de interfaces de solo lectura

`networkinventory.Discover(ctx)` observa interfaces, direcciones IPv4/IPv6 y flags
del sistema, sin modificar direcciones, rutas, zonas ni forwarding. No inicia
procesos ni listeners. Sus tipos Go son internos; no constituye todavía un
contrato administrativo Web/CLI/API.

Conserva los bits de la dirección del host; una dirección sin máscara tiene
`Prefix == nil`. `AdminUp` y `Running` no acreditan portadora física, velocidad o
conectividad. No se inventan gateway, DNS ni procedencia DHCP/estática.

En Linux, `device-backed` indica un enlace de dispositivo y también puede ser una
NIC virtual presentada por el hipervisor. `virtual` identifica una ruta virtual
del kernel. Los datos ausentes o no verificables quedan como `unknown`; loopback
se identifica por su flag. Otros sistemas conservan `unknown`, salvo loopback.

Se comparan dos observaciones completas y se rechazan cambios observables, sin
devolver datos parciales. No es una instantánea atómica del kernel. La cancelación
se comprueba entre llamadas; no interrumpe una enumeración estándar ya iniciada.

Límites del resultado: 256 interfaces, 256 direcciones por interfaz, nombres de
256 bytes y direcciones de hardware de 64 bytes. La enumeración inicial del
sistema puede asignar memoria antes de aplicar estos límites. Errores estables:
`network_inventory_unavailable`, `network_inventory_limit`,
`network_inventory_invalid_observation`, `network_inventory_changed`.

Pruebas desde la raíz del repositorio:

```sh
go test -race ./internal/networkinventory
go vet ./internal/networkinventory
go test -run '^$' -bench Discover -benchmem ./internal/networkinventory
```

El benchmark sintético no mide el kernel. La prueba Linux solo observa el entorno
donde se ejecuta; no demuestra soporte nativo de otras plataformas ni aplicación
de configuraciones, recuperación o paridad administrativa.
