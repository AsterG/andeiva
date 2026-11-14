# Compilador DHCP para Kea 2.6.3

[Componente confinado experimental](runtime.es.md), sin activación productiva;
sus pruebas nativas de paquetes/reinicio son independientes del compilador.

Sólo compilación determinista; no crea procesos, listeners, archivos de concesiones,
unidades, API, almacén ni cambios de red. Requiere calificación nativa antes de habilitar.

`Compile(dhcpserver.Config, []Binding)` reutiliza validación esquema 1. Assembly
aporta exactamente un binding por ámbito retenido: LAN estática seleccionada,
nombre kernel y `SubnetID` estable de 1 a 4294967294. Bindings excluidos de JSON;
validación no demuestra propiedad física. WAN, IPv6, nombres/IDs duplicados,
bindings faltantes/adicionales, wildcards/selectores y configuración incorrecta
se rechazan con `ANDEIVA_DHCP_KEA_INVALID`.

Assembly **debe conservar la asociación ámbito/SubnetID entre revisiones y
reinicios**. No derivarla del orden, truncar hashes, adoptar identidad antigua sin
prueba ni crear otra base de configuración. Aquí no hay asignador/historia ni
garantía de continuidad de concesiones.

Disabled valida los ámbitos retenidos y devuelve `Enabled=false`, `JSON=nil` y
digest vacío. El caller todavía debe drenar/observar recursos antes de declarar
deshabilitado. Enabled fija RAW sólo LAN, require-all, cero reintentos, lease/T1/T2,
gateway, DNS/NTP en orden y dominio opcional. Ordena/divide pools retirando
exclusiones y reservas; un pool vacío permanece vacío. Reservas MAC fuera de
pools dinámicos no autentican dispositivos. Se conserva matching DHCP client-ID
normal; no se aceptan reservas administrativas por client-ID.

Cada subred exige además una clase fija que coincida con su interfaz de ingreso, incluso al seleccionar por dirección en renovaciones. Clase DROP fija para giaddr/option82 de relay. Sin DDNS, hooks, control socket,
credenciales DB, opciones arbitrarias, rutas/ejecutables del caller ni DHCP4o6.
No genera nftables ni permiso forwarding/NAT. Aislamiento RAW, identificación,
política local y tráfico desconocido siguen siendo requisitos de runtime.

Memfile persistente solicitado en ruta fija
`/var/lib/kea/kea-leases4.csv`, limpieza horaria. **Nunca restaurarlo
desde una revisión de configuración**. Ownership, LFC confinado, cuotas,
reinicio, migración, disco lleno y pérdida de energía requieren pruebas reales.
`max-row-errors=1` todavía omite una fila corrupta en Kea 2.6.3 antes de fallar
con la segunda; cero sería ilimitado. `lease-checks=warn` evita reparación/borrado
automáticos, pero no prueba validez. Runtime debe rechazar estado histórico
corrupto/no probado antes de servir. `-t` no resuelve ese gate; no hay parser CSV nuevo.

Límites: 32 ámbitos, 32 pools declarados/ámbito, 256 exclusiones y 256 reservas/ámbito,
65.536 direcciones declaradas totales, 64 KiB entrada y 1 MiB salida. Intervalos sin
enumerar subredes. Un hilo, cola deshabilitada, una muestra estadística y stdout/WARN
no acreditan rendimiento, auditoría ni retención de logs. Digest sólo identifica
bytes generados, no revisión seleccionada/autoridad. No muta entradas; reordenar
conjuntos conserva salida, orden DNS/NTP se preserva deliberadamente.

```sh
go test -race ./internal/dhcpkea
go vet ./internal/dhcpkea
go test -run='^$' -bench=Compile -benchmem ./internal/dhcpkea
GOOS=windows GOARCH=amd64 go build ./internal/dhcpkea
```

Fixture sintética `../testdata/kea-2.6.3.json` comparada byte a byte. Root puede
validarla con Kea 2.6.3 verificado y `-t` en laboratorio aislado; no acredita ejecución
ni persistencia. Medición Linux/WSL: race 1,091 s; pequeño 9.991 ns/op / 4.593 B;
denso dos ámbitos 768.860 ns/op / 450.129 B. Tres ámbitos densos:49.321 B → 100.885 B;
cuatro exceden entrada y se rechazan. No benchmark appliance ni nuevo runtime
Docker/EKS. Revisión independiente y pruebas nativas pendientes.

Se omiten `cache-threshold` y `cache-max-age`: Kea 2.6.3 requiere configuración
explícita para activar la caché y rechaza un umbral cero configurado. La regresión
comprueba su ausencia. Este valor predeterminado no prueba durabilidad de leases;
queda repetir el parseo nativo tras los rechazos iniciales. Fuente:
`BaseNetworkParser::parseCacheParams` y `AllocEngine::setLeaseReusable`.

Referencias: [DHCPv4](https://kea.readthedocs.io/en/kea-2.6.3/arm/dhcp4-srv.html),
[clasificación](https://kea.readthedocs.io/en/kea-2.6.3/arm/classify.html) y fuente
2.6.3 `lease_file_loader.h`/parser DHCPv4.
