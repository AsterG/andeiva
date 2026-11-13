# Transporte del helper con selección durable

El protocolo3 agrupado no vuelve a escritores independientes antiguos. Sólo se
ensambla sobre un canal Unix autenticado por el supervisor; los wrappers heredados
verifican UID, GID y PID del kernel. El cliente sin privilegios envía preparación
canónica o una referencia. El helper reconstruye selección completa, G1, bancos,
scope y propósito. Un hash o boolean serializado no concede autoridad. La generación
del Work y la generación global son distintas. La preparación de sólo lectura
contrasta la expectativa con Startup, testigo guardado y baseline independientes;
no recibe rutas, comandos, TTL ni identidades del solicitante.

El controlador conserva exclusión hasta terminar llamada y respuesta, aunque el
cliente desaparezca. Otro escritor debe completar el handshake antes de abrir su
almacén. Una respuesta perdida cierra el canal sin repetición ni renovar plazos;
el guardian permanece independiente. Límite: tres artefactos de256KiB+4096bytes,
sin cambiar las cotas v1/v2.

Pruebas unitarias/race: frames malformados, scope/secuencia, planes sin verificar,
exclusión y credenciales Unix reales. Usan motores fixture: no prueban nftables
nativo, acceso al almacén entre procesos ni activación permanente. Integración,
despliegue nativo y recursos del helper ensamblado permanecen pendientes.

```sh
go test -race ./internal/firewallipc ./internal/previewruntime -run 'TestRouted(Codec|Client|Reply|Session|Inherited)V3' -count=1
go vet ./internal/firewallipc ./internal/previewruntime
```
