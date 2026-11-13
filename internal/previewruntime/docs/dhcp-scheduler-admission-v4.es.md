# Admisión del scheduler DHCP

Componente en desarrollo; validación nativa integrada pendiente.

El scheduler DHCP seleccionado omite un ciclo si la inspección u otra operación
ocupa el controlador. Crea el contexto existente de tres segundos sólo después
de adquirirlo y comprobar cancelación. Omitir un ciclo no envía solicitudes ni
cierra el canal. La cancelación libera el controlador.

La reconciliación pública conserva el contexto original y la espera bloqueante.
Se mantienen el límite agregado de tres segundos y los límites de cada RPC:
dos RPC de dos segundos siguen excediendo el agregado y cerrando el canal.
No cambian concesiones, confirmación, watchdog ni recuperación. No se implementan
presupuestos por fase, I/O cancelable del store ni recuperación general de timeout.

No se agregan workers, timers, colas ni estado persistente. Evitar la espera no
acredita una mejora medida de CPU/RAM; faltan adquisición y recursos nativos.
Rollback mediante reversión del código, sin cambiar la configuración seleccionada.

Ejecutar con Go 1.27.4 en Linux/WSL:

```sh
go test -race ./internal/previewruntime -run TestRoutedDHCPSchedulerV4 -count=1 -timeout=60s
go vet ./internal/previewruntime
go build ./internal/previewruntime
```

Las pruebas usan una conexión de protocolo privado real y una concesión simulada,
no un propietario DHCP ni kernel nativo. Cubren contención, cancelación al admitir,
canal conservado al omitir ciclos y límites individuales/agregados sin cambios.
Las dos regresiones de contención usan tiempo real acotado porque esperar un mutex
no avanza el reloj de `testing/synctest`; los límites usan tiempo virtual.
