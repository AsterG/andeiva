# Ejecutor IPv4 estático en namespace — NET-EXECUTOR-001

Responsable: ejecutor de red. Estado: implementación para revisión, sólo
cualificación aislada. Lo consume el laboratorio aislado de routing; sin conexión
a API, CLI, runtime o helper privilegiado del appliance.

`New(supervisorLifetime, trustedNamespaceFD)` duplica y fija un descriptor de
namespace de red Linux. Verifica el tipo y rechaza los namespaces actual y de
PID 1. El supervisor privilegiado debe arrancar en el namespace del host, poseer
todos los escritores del namespace desechable y mantener el contexto de
recuperación hasta terminar `Restore`. Esta autoridad nunca procede de HTTP.
Se admite un propietario por namespace dentro del proceso; el supervisor garantiza
la exclusividad externa. Un cierre abrupto pierde el plan en memoria.

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

Vincula observaciones confiables mediante `networkplan.Bind`, verifica identidad
antes de cada cambio y comprueba semánticamente direcciones y todas las rutas,
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

Comandos simulados y rechazos read-only de namespaces. Pendientes: ejecución real
privilegiada, Debian, revisión independiente, ejecución en contenedor y mediciones
CPU/RAM del appliance. Sin integración Docker/EKS/Helm ni declaración de release
o cierre del hito.
