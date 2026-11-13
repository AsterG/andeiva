# Retiro seleccionado entre arranques del OS

El perfil experimental v4 está separado del reinicio de servicio v3. Reiniciar
el servicio conserva Running o revierte una operación sin confirmar. Reiniciar
el OS selecciona Startup. Ningún camino restaura una concesión DHCP ni un token
de expiración anterior.

Root debe completar su parada normal y escribir el recibo v3 de 4096 bytes tras
drenar procesos y retirar el namespace anterior. El helper v4 recibe su FD
O_RDONLY propiedad de root y el binding de bootstrap al digest completo y la
identidad nueva real. Comprueba BootID actual del kernel, namespace propio fuera
del host y UID/GID de servicio iguales. BootID y RunID deben cambiar. Los números
de inode pueden repetirse entre boots; cada namespace debe diferir de su host.

`RoutedRebootScopeEvidenceV4` separa BOOTTIME del drenaje viejo y de observación
nueva. Ambos son positivos; nunca compara sus magnitudes. Los deadlines DHCP
anteriores quedan como historia inmutable, nunca como vigencia del nuevo boot.
El mismo almacén seleccionado registra `configuration.routed-reboot-scope.v4`,
trabajo/identidad/recibo/readback exactos y `scope_retired`. No afirma retirada
WAN observada, compensación ni restauración.

G1/R2 completo debe encontrar exactamente el trabajo anterior seleccionado.
Un recibo viejo no permite saltar una instancia. `PrepareRebootScopeViewV4`
deriva Startup, Saved y trabajo para ensamblado confiable del motor. Luego el
helper prueba tablas/IPv4 vacíos, forwarding cerrado y listeners reales según
el contrato existente. `routed_reboot_scope.v4` negocia separado de v3 y
`reboot_scope` sólo recibe referencia de trabajo. Caller no aporta boot, reloj
ni prueba. Fence persistente y anchor opaco de attach siguen obligatorios.

El terminal DHCP anterior se archiva mediante reservas/selector existentes antes
de aplicar LAN del nuevo Boot. WAN queda sin autoridad de concesión seleccionada;
sólo una concesión nueva del propietario nuevo permite activación posterior.
Outcomes pendientes y deadlines UTC originales no cambian. No libera reservas
ni boundaries interrumpidos sin prueba. Recibos ausentes, parciales o viejos
bloquean. No se afirma recuperación ante power-loss, suspensión o snapshots VM.

Pruebas con almacén/pools reales, dobles físicos y pipes explícitos: reloj nuevo
menor, inodes reutilizados, retiro antes de LAN, Startup/Running, trabajo viejo
inmutable, deadlines pendientes, G1 corrupto, ámbito incorrecto, ausencia de
anchor/fence y separación v3/v4. Siguen pendientes reboot OS nativo completo,
FD root, continuidad de tráfico y mediciones CPU/RAM.

```sh
go test -race ./internal/configpoc ./internal/firewallipc ./internal/previewruntime -run 'TestRouted(RebootScopeV4|FreshScopeV3)' -count=1
go vet ./internal/configpoc ./internal/firewallipc ./internal/previewruntime
go build ./...
bash scripts/check-config-platforms.sh
```

El recurso Root agrupado compara BootID actual del kernel con metadata y el
recibo decodificado. Selecciona un único perfil: v3 para el mismo BootID, v4
cuando cambia. Ambos conservan FD14 exclusivo del helper; la API sólo recibe
una bandera de capacidad, sin binding del recibo. Rechaza perfiles mezclados,
falta de binding del helper y una factory API con perfil distinto al bootstrap.
La factory v4 usa `PrepareRebootScopeViewV4(...).Saved` para el motor baseline.

Boot admite inventario local distinto sin servicios únicamente mediante
`RoutedNoServicesTransitionV3`: Saved/historia autenticados, interfaces canónicas
derivadas exactamente de la red y cero definiciones de servicios en ambos lados.
No reescribe Saved. La ausencia real de listeners y el trabajo seleccionado siguen
siendo requisitos independientes. Tests cubren inventario estático y LAN DHCP;
rechazan historia ausente, inventario modificado, Saved sustituido y estado local
inesperado. No acreditan reboot OS nativo ni transferencia FD root del perfil v4.

```sh
go test -race ./internal/configpoc ./internal/previewruntime -run 'TestRouted(BootNoServicesV3|RetirementBootstrapV[34])' -count=1
```
