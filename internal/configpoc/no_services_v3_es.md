# Inventario enrutado sin servicios locales

ADR-056 permite una proyección interna acotada para el candidato enrutado.
Se deriva el inventario local de la red canónica: direcciones exactas LAN y WAN
en el perfil estático admitido, o solo LAN estática cuando WAN usa DHCP.
No inventa direcciones DHCP, define servicios, concede gestión, crea reglas
Forward/NAT ni modifica SSH/HTTPS del host.

La excepción exige **cero definiciones de servicios**, incluidas las deshabilitadas.
El inventario anterior debe estar vacío o coincidir exactamente con la red
enrutada anterior. Una fuente schema-4 sin red solo autoriza el cambio si su
inventario está vacío. Las políticas con definiciones de servicios conservan
su revisión exacta y no reciben esta excepción. Un `local_services_config`
de API distinto de Running sigue rechazado, aunque coincida con lo derivado.

Stage y Replace del propietario derivan el candidato bajo el bloqueo y las
validaciones existentes de propiedad y generación. No cambian Running ni
Startup. Commit conserva el snapshot anterior completo para compensación.
Rollback carga el bundle histórico autenticado y verificado y conserva su
revisión local original; nunca reconstruye contenido histórico. Se mantienen
plazo de confirmación, trabajo seleccionado, auditoría y recuperación.

`RoutedNoServicesTransitionV3` es un predicado puro sobre contenido y hashes
canónicos; no concede autoridad. Boot/restart deben autenticar los bundles
originales y conservar la lectura independiente de red, tablas y listeners.
El motor agrupado verifica las tablas propias y las observaciones de listeners
antes de efectos; el adaptador nativo limita esas lecturas al namespace retenido
del gateway.

Las pruebas usan coordinador/store y motor agrupado reales con I/O simulado.
Cubren servicios habilitados y deshabilitados, inventario ajeno, hashes alterados,
orden, metadatos de API, reemplazo/concurrencia, Startup intacto, rollback retenido
y rechazo de listeners/tablas ajenos:

```sh
go test -race ./internal/configpoc ./internal/routedactivation -run '^TestNoServicesV3' -count=1
go vet ./internal/configpoc ./internal/routedactivation
```

Activación, restart, rollback y mediciones de recursos en Debian siguen como
gates nativos separados. Estas pruebas no demuestran comportamiento del kernel.
No se añade motor, servicio, listener, timer, esquema persistente ni dependencia.
