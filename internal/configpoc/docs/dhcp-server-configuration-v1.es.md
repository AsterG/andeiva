# Configuración DHCP LAN preparada

La política routed versión 2 incorpora el objeto obligatorio `dhcp_server`, con el esquema 1 existente del servidor DHCPv4. La versión 1 exige que esté ausente y conserva sus bytes canónicos y hashes. La configuración exterior sigue en esquema 6, el composite en 7 y network en 1. Se reutilizan un único almacén y coordinador: DHCP forma parte de la revisión routed/firewall existente.

La canonicalización copia todos los datos anidados. Ordena ámbitos, pools, exclusiones y reservas de forma determinista; conserva el orden de DNS y NTP. Los bindings se derivan de las LAN estáticas del network seleccionado, no de un inventario runtime enviado por el cliente. Esto valida coherencia deseada, no ownership físico, disponibilidad de interfaces ni ejecución del servidor. La configuración deshabilitada sigue validada y conservada.

El feature persistente `configuration.routed-dhcp-server.v1` acompaña a la primera operación seleccionada que contiene esta política. La publicación de Candidate/configuración también exige el feature. Descartar el Candidate no lo elimina. Los lectores anteriores deben rechazar antes de reconciliar; rollback no permite quitarlo para arrancar un binario antiguo. No hay migración implícita de almacenes anteriores.

La autoridad routed confiable debe implementar `RoutedDHCPServerSupportV1` y declarar soporte explícito. Ninguna autoridad existente lo habilita. Sin soporte se rechaza la admisión antes del mantenimiento de reservas, claims o publicación; abrir un almacén marcado se rechaza antes de recuperación y efectos de motores. La capacidad no es prueba física. Sólo podrá declararse cuando activación, readback efectivo, compensación y apagado completo incluyan al servidor; observar correctamente nft no basta.

Stage, Commit confirmado, Save y rollback usan la transacción conjunta existente. El rollback de configuración no debe revertir ni descartar concesiones emitidas. No se añaden base de concesiones, launcher Kea, unidad, endpoint, UI, activación runtime ni despliegue. El futuro adapter debe probar persistencia, presión de almacenamiento, servicio real, deshabilitación sin recursos y recuperación antes de habilitarse.

Se conservan las cotas: entrada DHCP de 64 KiB y envelope actual de operación de 8 KiB. Una configuración DHCP válida aislada puede exceder el transporte preparado: se rechaza sin truncarla. No se aumentan cuotas. El forecast de metadatos reserva el tamaño del feature. Mediciones de recursos runtime pendientes.

```sh
go test -race ./internal/dhcpserver ./internal/routedmodel ./internal/configpoc -run 'TestCanonical|TestDHCPServer|TestReserveEnvelope'
go vet ./internal/dhcpserver ./internal/routedmodel ./internal/configpoc
go build ./...
go test ./internal/dhcpserver -run '^$' -bench '^BenchmarkCanonical$' -benchmem
```

Usar el toolchain Go del proyecto. `TestDHCPServerOldReaderBarrier` requiere además `-reclaim-old-reader=/ruta/absoluta/prior-configpoc.test`, compilado desde la fuente anterior con su adapter existente `TestReclaimPriorReader`. Sin ese binario el caso se omite: no constituye PASS de compatibilidad. Los tests usan almacenes temporales reales y motores simulados; no un servidor DHCP nativo.
