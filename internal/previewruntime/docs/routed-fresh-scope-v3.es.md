# Ámbito nuevo tras parada normal del servicio

Integración experimental del almacén seleccionado: distingue boot del sistema
e instancia del servicio. Un mismo BootID puede usar otro RunID y namespace
gateway sólo con recibo root autenticado y readback real de IPv4/tablas vacías.
Las reglas de propiedad de snapshots estáticos no cambian.

Root preasigna un archivo regular de 4096 bytes, propietario/grupo 0:0, modo
0600, un enlace, sin ACL. Tras esperar a los hijos y cerrar el namespace anterior,
escribe `RootRetirementReceiptV3` en el mismo archivo y ejecuta fsync. El codec
contiene ámbito anterior, digest de metadata, instante BOOTTIME original de
drenaje y digest del JSON canónico sin su campo de integridad; completa el slot
con espacios. Ese digest detecta escrituras incompletas; el FD root autentica
al emisor.

Root liga el digest de los 4096 bytes a la identidad nueva y entrega al helper
sólo FD O_RDONLY y `RoutedFreshScopeBindingV3`. El helper duplica y revalida el
FD, lee el trabajo seleccionado, reutiliza `PrepareBoot`/`Observe`, exige ausencia
de toda tabla (incluido gate de lease) y observa forwarding IPv4/IPv6 cerrado.
Root debe retrasar los sockets del motor DHCP hasta boot LAN; no se omite la
comprobación real de ausencia de listeners.

El ensamblado llama `PrepareServiceRestartViewV3` con la identidad anterior del
recibo verificado. Su metadata Target/Saved seleccionada configura el motor;
no debe reemplazar Saved por Startup. `prepare_boot` privado vuelve a leer trabajo
y recibo y compara objetivo/baseline antes de preparar en sólo lectura. La
metadata sola nunca autoriza efectos.

La API negocia `routed_fresh_scope.v3` junto a integridad e inventario; DHCP es
independiente. `fresh_scope` sólo recibe referencia de trabajo seleccionado.
No admite recibo, identidad, deadline ni bandera de prueba en peticiones. El
mismo almacén registra `configuration.routed-fresh-scope.v3` persistente. DHCP
termina como `scope_retired`, no `withdrawn` ni `restored`; conserva trabajo y
deadline original. Conserva outcomes y deadlines de confirmación pendientes.
Reiniciar el servicio conserva Running, LastGood y Startup seleccionados, aunque
Running difiera de Startup. Un commit pendiente vuelve a su Previous exacto;
nunca se confirma implícitamente. El registro tipado liga origen y recibo; el
helper deriva el mismo objetivo de su lectura completa antes de efectos.
Reiniciar el OS sigue seleccionando Startup y no queda habilitado por este
perfil de igual BootID. Historia seleccionada y recibo
retenido por helper deben coincidir; dirección IP o token previo no bastan.

Las pruebas focales usan archivos/pools reales y dobles explícitos de autoridad
física. Cubren reinicio completo/pendiente con igual BootID, deadlines intactos,
continuación del audit exacto de retirada, rechazo de prueba enviada por caller
y FD inválido. Faltan calificación nativa root drain/recibo/FD/namespace/helper
y recursos. Muerte de root sin recibo completo bloquea recuperación; limpieza
ExecStopPost/crash sigue como gate independiente pendiente. Suspensión, pausa
de VM y snapshots no están soportados. No se afirma activación del host.
Paradas repetidas durante una recuperación boot-boundary aún pendiente pueden
retener ambos slots System; otro boundary queda bloqueado hasta disponer de
retirada probada por separado. Este incremento no descarta esas reservas.

```sh
go test -race ./internal/configpoc ./internal/previewruntime ./internal/firewallipc -run 'Test(RoutedFreshScopeV3|RootRetirementReceiptV3|RoutedOSBootBoundary|ColdContinuationV1)' -count=1
go vet ./internal/configpoc ./internal/previewruntime ./internal/firewallipc
```
