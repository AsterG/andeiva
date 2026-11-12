# Ejecutor IPv4 estático en namespace — NET-EXECUTOR-001

`ObservedSnapshot` captura inventario IPv4 vacío real sin plan deseado ni PlanHash.
PrepareObserved sólo recibe bindings físicos autenticados por el supervisor; no
escribe direcciones/rutas ni crea transacciones. VerifyObserved comprueba baseline
real. RecoverObserved exige además identidad inmutable original retenida sólo por
NewInOwnedNamespace; no concede propiedad L3. ObservedMatchesPrepared compara todos
los hechos físicos cuando se entrega posteriormente un plan deseado real. Igualdad
no es autorización. El perfil inicial admite dos enlaces propios y loopback
opcional, sin direcciones/rutas IPv4. Interfaces ya configuradas y leases DHCP
continúan fuera de este perfil.

Responsable: ejecutor de red. Estado: cualificación aislada verificada;
PR/integración pendientes. Lo consume el laboratorio aislado de routing; sin conexión
a API, CLI, runtime o helper privilegiado del appliance.

`New(supervisorLifetime, trustedNamespaceFD)` duplica y fija un descriptor de
namespace de red Linux. Verifica el tipo y rechaza los namespaces actual y de
PID 1. El supervisor privilegiado debe arrancar en el namespace del host, poseer
todos los escritores del namespace desechable y mantener el contexto de
recuperación hasta terminar `Restore`. Esta autoridad nunca procede de HTTP.
Se admite un propietario por namespace dentro del proceso; el supervisor garantiza
la exclusividad externa. Un cierre abrupto pierde el plan en memoria.

`NewWithHost(supervisorLifetime, targetFD, trustedHostFD)` admite un descriptor de
host abierto por el gestor de servicios antes de restringir privilegios. Duplica
ambos y verifica nsfs/tipo de red, host igual al namespace actual del supervisor
y destino distinto del host. Cerrar los descriptores del llamador no invalida los
propios. El ensamblaje confiable establece la procedencia del host; un inodo no
la demuestra. Nunca aceptar esta autoridad desde HTTP, IPC no confiable o rutas/
descriptores arbitrarios. `New` conserva el control de `/proc/1/ns/net` y rechaza
si es inaccesible; no se agregan capacidades ni se debilita el control del host.

`Apply` requiere una revisión canónica `networkplan.Revision`, IPv4 estático,
DNS `none` y prefijos 1–30. Ningún enlace puede tener direcciones IPv4 previas y
todas las tablas de rutas IPv4 deben estar vacías, incluso loopback/local.
Los enlaces ya deben tener el estado administrativo requerido. No admite migración
de direcciones existentes ni LAN administrativa, DHCP, DNS, estado de enlaces,
policy routing, IPv6, NAT, firewall, sysctls, VPN ni red del host. No es un gestor
de red operativo del appliance.

Sólo ejecuta `/usr/bin/nsenter` y `/usr/bin/ip` fijos: namespace heredado en FD 3,
entorno fijo, ejecutables/rutas propiedad de root sin escritura no autorizada,
límite de dos segundos y 256 KiB por flujo de salida. Sin shell, rutas/comandos
arbitrarios, instalación, listeners o workers permanentes. Se presupone root,
kernel e instalación confiables y propiedad exclusiva del namespace; otro proceso
root hostil queda fuera del modelo de amenazas.

Vincula observaciones confiables mediante `networkplan.Bind`. Une direcciones
IPv4 con nombre/índice/MAC de dos lecturas iguales de
`ip -j link show`. El selector IPv4 omite MAC y enlaces sin IPv4; una respuesta
vacía de direcciones no equivale a un inventario vacío de enlaces. Verifica la
identidad antes de cada cambio y comprueba semánticamente direcciones y todas las rutas,
incluidas las conectadas/locales del kernel. Rechaza atributos desconocidos en
direcciones/rutas. No demuestra conectividad ni activa forwarding o inspección.
Rechaza miembros JSON duplicados con semántica exacta de nombres JSON.
Nunca libera tráfico desconocido para capturarlo ni permite eludir inspección.
`Verify` repite la lectura del plan activo sin cambios: una deriva o lectura no
disponible bloquea permanentemente la instancia.

Llamar `Restore` antes de `Close`. La compensación usa la vida del supervisor,
independiente de la solicitud, elimina sólo adiciones exactas intentadas y verifica
el snapshot controlado original. Cambio de identidad, fallo de comando o
restauración diferente bloquean permanentemente la instancia. Verifica la
identidad antes de cada eliminación; no es una
comprobación atómica frente a escritores ajenos con CAP_NET_ADMIN, excluidos por
la propiedad exclusiva. No abrir otra instancia para reintentar admisión:
conservar evidencia y destruir únicamente el fixture
desechable propio. `Close` sólo cierra el descriptor; no acredita restauración
ni persistencia. Rollback de código: mantener sin conectar o revertir el commit;
no cambian formatos persistentes, servicios ni configuración del host.

Pruebas sin privilegios ni cambios de red, Go 1.27.4 en Linux/WSL:

```sh
go test -race ./internal/networkexecutor ./internal/networkplan ./internal/networkinventory
go vet ./internal/networkexecutor
go build ./internal/networkexecutor
GOOS=linux GOARCH=arm64 go build ./internal/networkexecutor
GOOS=windows GOARCH=amd64 go build ./internal/networkexecutor
GOOS=darwin GOARCH=arm64 go build ./internal/networkexecutor
```

Pruebas con comandos simulados y controles read-only de namespaces. Revisión
independiente de root y arquitectura sobre `460fece`: sin hallazgos críticos,
altos o moderados. Repetición independiente de race (`-count=3`): PASS en 1.647 s.

Cualificación Debian 13 amd64 de `460fece` (prefijo SHA-256 del binario `590a4005`):
PASS en los tres namespaces para apply/readback/restauración tipados, TCP/UDP SNAT
con tuplas conntrack reales, ICMP relacionado, denegación IPv6 y reversa no
solicitada, revocación TCP existente, routing sin NAT y NAT sin autorización de
forwarding. Limpieza e invariantes externos del host PASS. Helper limitado a
SYS_ADMIN/NET_ADMIN con FD 0 de host entregado por el supervisor; el supervisor
root cargó aparte el módulo conntrack requerido.
Una ejecución: 4.408428 s transcurridos, CPU 1.116154 s, pico 32,321,536 bytes.
No representa un benchmark de capacidad o rendimiento del appliance.

Siguen sin soporte: migración de LAN administrativa existente, DHCP, activación
runtime del appliance y recuperación durable tras crash. Ejecución en contenedor
y presupuesto de recursos del appliance sin cualificar. Sin integración
Docker/EKS/Helm ni declaración de release o cierre del hito. Requisitos en las
guías EN/ES/PT del runner.
