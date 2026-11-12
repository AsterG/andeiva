# Contrato preparado de configuración enrutada

Este paquete contiene el modelo canónico IPv4 puro del adaptador enrutado aislado.
No realiza E/S ni autoriza cambios de red. `routednft` conserva sus alias y la
identidad del error; las revisiones y los lotes compilados mantienen sus bytes.

`configpoc.CanonicalRouted` valida un sobre preparado de esquema 6: política
explícita de laboratorio, denegación predeterminada, sin reglas heredadas ni
servicios locales. La entrada normal `Canonical` y los motores actuales de
firewall, servicios locales y simulación lo rechazan. Este cambio no activa
lectores, API, coordinador ni runtime para el esquema 6.

Se validan interfaces, zonas, orden, habilitación explícita, CIDR IPv4 y puertos
TCP/UDP. Se rechazan protocolos no admitidos, inspección obligatoria y referencias
NAT o rutas ambiguas. El alcance sigue siendo experimental.

Ejecuta los comandos reproducibles de [la guía principal](README.md) desde la
raíz con la versión Go fijada por el proyecto. Las pruebas comparan hashes del
compilador anterior, conservan formatos heredados y comprueban el rechazo por
consumidores reales. Compilar para otro sistema no acredita ejecución nativa.
Estas pruebas no modifican interfaces, reglas, rutas ni forwarding del host.
