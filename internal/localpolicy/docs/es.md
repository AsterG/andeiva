# Servicios locales: compilador aislado

Esta POC para desarrollo valida declaraciones y genera JSON; no instala nada.
Desde la raíz del repositorio, con la versión de Go fijada por el proyecto:

```sh
go test ./internal/localpolicy
go test -race ./internal/localpolicy
go vet ./internal/localpolicy
go test ./internal/localpolicy -run '^$' -bench BenchmarkCompile -benchmem
GOOS=windows GOARCH=amd64 go build ./internal/localpolicy
GOOS=darwin GOARCH=arm64 go build ./internal/localpolicy
```

El detector de carreras requiere plataforma compatible y compilador C. No se
necesitan contenedores ni operaciones de red privilegiadas. Fuzzing opcional:
`go test ./internal/localpolicy -fuzz FuzzDecode -fuzztime 10s`.

Límites: 256 KiB por documento, 32 interfaces, 64 servicios, 4.096 reglas
derivadas y 4.096 tuplas de listeners declarados. Cada servicio permite hasta 16
endpoints y 16 bindings; cada binding admite hasta 64 prefijos de origen. Son
límites de validación, no capacidad del appliance demostrada. Las pruebas cubren
el límite de expansión 4.096/4.097 y cada predicado de las reglas IPv4/IPv6 TCP/UDP.
CI ejecuta pruebas puras, fuzzing acotado y compilación Windows/Linux/Darwin;
no activa este paquete ni modifica políticas de red.

`DefaultManagement` recibe una interfaz LAN de inventario confiable, dirección
local exacta y prefijos de origen explícitos. Declara TCP 443 con autenticación
obligatoria; no inicia HTTPS. `Bindings` permite seleccionar una o varias
interfaces LAN, WAN u otras. Cada binding WAN requiere `WANOptIn: true`. Las zonas
y direcciones deben coincidir con el inventario. IPv4 e IPv6 usan bindings
separados con orígenes de la misma familia. Se rechazan comodines y prefijos /0.

`Canonical` valida y calcula la revisión de una copia independiente. `Compile`
genera reglas con propietario y un lote JSON para crear una tabla. `Preview`
muestra permisos añadidos/eliminados y marca los cambios administrativos como
dependientes de confirmación. `EffectiveView` filtra las reglas por servicio;
editar su resultado no modifica declaraciones. `Reconcile` compara observaciones
aportadas y detecta listeners/reglas ausentes o residuales. La coincidencia no
demuestra el estado real del kernel.

La tabla es `inet andeiva_local_poc`, hook input, prioridad 10 y política drop.
No aplicarla en el host del appliance. No incluye tráfico de control ICMP/IPv6,
loopback, recuperación administrativa, autenticación real, inspección de sockets
ni reemplazo atómico. Un drop de otra cadena base sigue siendo efectivo. No genera
permisos de forwarding ni NAT. No se proporciona un comando de instalación.

Las pruebas cubren declaraciones, conflictos, dependencias, cambio de puerto,
permisos al deshabilitar, múltiples interfaces, IPv4/IPv6, diferencias entre
observaciones aportadas, serialización y compilación concurrente. No prueban
tráfico real, recuperación tras caída, Commit Confirmed, auditoría ni transacciones
persistentes. El benchmark mide tiempo y asignaciones del compilador, no memoria
del appliance ni rendimiento de paquetes.

El 2026-11-10, en WSL/Linux amd64, Go 1.27.3, Intel i7-1370P y
`GOMAXPROCS=2`, tres muestras de un segundo midieron 30,580–34,950 µs
para un servicio/regla (aproximadamente 19,53 kB asignados por operación,
190 asignaciones). `BenchmarkCompileCapacity`, con 64 servicios y 4.096 reglas,
midió 70,991–89,839 ms y aproximadamente 73,14 MB asignados por operación.
Las asignaciones acumuladas no son el pico de memoria residente. Antes de integrar
el runtime se debe limitar la compilación concurrente y medir memoria en el
appliance objetivo; estos resultados no establecen una tasa segura de solicitudes.

No hay componentes instalados que detener o desinstalar. Actualizar o retirar el
paquete requiere revisión normal del código. La integración depende de aprobar el
[diseño transaccional compartido](../ADR.md), implementar un observador confiable y
probar en Debian aislado. System → Local Services y Firewall → Effective Policies
son vistas Web/CLI/API previstas, no implementadas aquí. VPN, DNS, DHCP, NTP,
portal, reverse proxy y WAF sólo tienen identidades de servicio reservadas.
