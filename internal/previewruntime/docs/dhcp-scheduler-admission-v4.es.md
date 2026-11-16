# Admisión del scheduler DHCP

Componente en desarrollo; validación nativa integrada pendiente.

El scheduler DHCP seleccionado omite un ciclo si la inspección u otra operación
ocupa el controlador. Crea un único contexto de intento de 30 segundos sólo después
de adquirirlo y comprobar cancelación. Omitir un ciclo no envía solicitudes ni
cierra el canal. La cancelación libera el controlador.

La reconciliación pública conserva el contexto original y la espera bloqueante.
Cada RPC conserva su límite de tres segundos. Dos RPC secuenciales de dos
segundos pueden completar el intento automático; un llamador manual con límite
de tres segundos sigue cerrando el canal en esa secuencia. El contexto no se
renueva entre fases. Prevalecen la cancelación o un plazo menor del llamador.
No cambian concesiones, confirmación, watchdog ni recuperación. No se implementan
presupuestos por fase, I/O cancelable del store ni recuperación general de timeout.
El límite de 30 segundos es cooperativo: I/O o locks bloqueantes pueden retrasar
el retorno y el cierre. Timeout no demuestra rollback completo; se retienen las
referencias de recuperación.

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
canal conservado al omitir ciclos, presupuestos de RPC secuenciales, límites
manuales o menores y cancelación/drenaje del scheduler. Los negativos de concesión
vencida siguen en `internal/networkexecutor`; estas pruebas no califican la
publicación durable en el límite completo de 30 segundos.
Las dos regresiones de contención usan tiempo real acotado porque esperar un mutex
no avanza el reloj de `testing/synctest`; los límites usan tiempo virtual.
