# Autoridad de configuración enrutada

El supervisor puede suministrar al plano de control V2 una autoridad enrutada
exclusiva. La entrada administrativa no selecciona namespaces, pools, rutas de
artefactos, identidades del helper ni capacidades de activación. Firewall 6 y
servicios locales 3 forman una candidata 7 y una transacción protegida conjunta.

Antes de armar, el coordinador selecciona objetos tipados de propiedad,
dependencias e identidad con el Intent y las reservas existentes. El helper
verifica ese plan y su plazo original, aplica lotes compilados y lee el estado
efectivo. Confirm utiliza la operación original y la revisión de Pending;
Save copia Running confirmado completo a Startup.

Cerrar API/catálogo conserva helper y tráfico. Reabrir el controlador conserva
lo confirmado; los commits pendientes siguen la compensación de reinicio
existente. Otro helper o arranque no puede adoptar una identidad anterior ni
inventar un plazo nuevo.

`TestRoutedPhysicalCoordinatorConfirmedLifecycle` utiliza almacenamiento,
autenticación, reservas físicas, compiladores y guardian reales con transporte
kernel/red simulado. No acredita tráfico real, recuperación de un helper nuevo
ni arranque. Boot agrupado e IPC productivo siguen bloqueados hasta validar su
integración. El router V2 rechaza mutaciones V1; el despacho de reintentos V1
migrados conocidos aún requiere integración. Consumo de recursos pendiente de
medición; estas pruebas no acreditan capacidad del appliance.

Prueba Linux: `go test -race ./internal/configpoc ./internal/previewruntime
./internal/localnft ./internal/routedactivation`.
