# Runtime preparado de operaciones

`OpenOperationsRuntimeV2` conecta el helper autenticado v2, el adaptador con plazo
absoluto y el almacén seleccionado con sus reservas existentes. No abre un escritor
v1, prepara reservas, migra configuración ni activa una opción de instalación.
El arranque en frío conserva las comprobaciones de recuperación del coordinador.

La API conserva sesiones, TLS, origen, CSRF y RBAC. Las escrituras nuevas v1 se
rechazan con `ANDEIVA_V2_OPERATIONS_REQUIRED`. `GET /api/v2/config/current` consulta
las proyecciones global y firewall reales bajo el mismo bloqueo.

`GET /api/v2/network/interfaces` requiere un proveedor confiable del namespace del
helper. Si falta, responde no disponible; nunca inspecciona el host de la API como
alternativa. Solo expone nombre, MAC, MTU, enlace, tipo y direcciones/prefijos.

Cerrar la API no elimina reglas ni namespaces. El helper conserva la política
confirmada y revierte las pendientes según su plazo independiente. Las pruebas
usan almacén y socket Unix reales con motores simulados; no certifican redes del
host, instalación permanente ni arranque en frío del grupo enrutado.

La característica seleccionada `configuration.routed-composite.v1` añade
proyecciones schema7 y el namespace `routed`. Stage captura ambas candidatas;
si se omite la configuración local, conserva exactamente su revisión activa.
No sobrescribe candidatas existentes. La identidad del grupo se correlaciona con
la auditoría protegida de Stage, sin fijar el catálogo para siempre. Current
incluye las vistas compuestas y `domain_generations` decimales; network es alias
de firewall. Startup permanece independiente y puede conservar schema4.

El ensamblaje no activa esa característica. La migración privada en frío verifica
el grafo seleccionado, el estado efectivo y la capacidad antes de publicar nuevos
envoltorios y auditoría; no cambia los componentes. Commit, Confirm y Rollback
enrutados se rechazan antes de Intent hasta integrar la autoridad agrupada.
Una configuración local diferente se rechaza antes de reservar mientras falte
su prueba de recuperación administrativa. Estos controles no equivalen a una
activación enrutada verificada ni a disponibilidad para producción.

En Linux ejecutar con `go test -race` los patrones `TestRuntimeServiceV2`,
`TestRuntimeOperations`, `TestRuntimeNetworkInventory` y `TestRuntimeV2`; después
`go vet` de configpoc/adminapi/previewruntime y `go build ./...`.
