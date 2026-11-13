# Runtime DHCP seleccionado V3

Integración experimental para un namespace de red propio distinto del host.
Los perfiles estáticos conservan su protocolo y significado de snapshots.
No implementa adopción de interfaces del host, servidor DHCP, NAT, DNS ni
forwarding seguro frente a suspensión.

El ensamblado root entrega `RoutedHelperOptionsV3.DHCP`: adapter LAN
seleccionado, descriptores target/host fijados, red canónica, propietario fijo
y callback `Current`. Este debe autenticar el canal heredado de escritor único
del propietario DHCP separado, PID/start/incarnation, secuencia y deadline
BOOTTIME absoluto original. La API no puede proporcionar esos hechos.
La API habilita `RoutedDHCP` y recibe `runtime.DHCP`; el ensamblado confiable
llama `Reconcile(ctx)` ante eventos del propietario y `Withdraw(ctx)` antes de
cambios de configuración incompatibles. Este incremento no conecta el productor
automáticamente ni expone un endpoint HTTP de leases.

El canal privado negocia `routed_dhcp_selected.v3` después de integridad e
inventario. Begin/current y retire reciben objetos vacíos. Apply/open/withdraw/
live reciben sólo el hash del trabajo seleccionado; verify recibe hash del
snapshot y estado. El helper verifica independientemente el grafo G1/R2 completo
antes de efectos. Un hash localiza el trabajo; no prueba propiedad.

Secuencia: cerrar gate y forwarding, capturar grant autenticado, seleccionar
trabajo preparado en el almacén existente, aplicar WAN, observar estado real,
seleccionar aplicado, preparar y leer token kernel acotado, abrir sin recrearlo
y habilitar forwarding verificando gate/política. La renovación actual retira
y archiva la WAN previa antes del próximo grant, con interrupción incluso si
la dirección coincide. La autoridad sin cambios sólo verifica el token vigente;
no extiende su deadline.

La pérdida del propietario o un bloqueo persistente de integridad provoca cierre
y retirada mediante el helper retenido. La expiración kernel no depende de que
API/helper sigan vivos. La recuperación seleccionada precede al boot LAN,
retira únicamente el delta WAN autenticado, lo archiva y libera el adapter LAN.
Sólo un terminal seleccionado exacto de retirada permite reconstruir un gate
cerrado; nunca un token vivo. Un namespace distinto necesita prueba de ámbito
nuevo; el reinicio normal del servicio con igual BootID y la retirada del ámbito
siguen pendientes de integración. Una prueba insuficiente bloquea recuperación.

Las pruebas focales con race cubren negociación, rechazo de autoridad en
peticiones, historia real del almacén, orden de efectos, pérdida del propietario,
retirada, replay, recuperación de gate cerrado y rechazo de forwarding ajeno.
Las pruebas unitarias de runtime usan dobles explícitos de kernel/propietario;
no acreditan forwarding nativo. Reproducción:

```sh
go test -race ./internal/networkexecutor ./internal/firewallipc ./internal/configpoc ./internal/previewruntime -run 'Test(RoutedDHCP|LeaseSelectedV3Archived|LeaseForwardingV3|RoutedCodecV3|RoutedSessionV3)' -count=1
go vet ./internal/networkexecutor ./internal/firewallipc ./internal/configpoc ./internal/previewruntime
```

Pendientes: calificación nativa productor/runtime seleccionado, excepciones de
control local DHCP con política real, readback del perfil forwarding/sysctl,
recuperación de ámbito nuevo con igual BootID, recursos y revisión independiente.
Las pruebas aisladas anteriores de lease/gate no prueban estas combinaciones.
Sólo ejecución continua: no se garantiza suspensión, pausa/snapshot de VM ni
retirada de paquetes ya encolados. No se afirma readiness productivo ni activación
del host.
