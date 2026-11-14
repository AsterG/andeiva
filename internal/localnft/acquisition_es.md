# Control Local-In de adquisición DHCP

Implementación de desarrollo bajo ADR-063; la validación integrada de renovación está pendiente.

El motor enrutado deriva una regla de la red seleccionada canónica cuando su WAN usa DHCP: IPv4 entrante por esa WAN, UDP de puerto 67 a puerto 68. Forma parte de la tabla INPUT propia `andeiva_local` y de su lectura completa. WAN estática y red enrutada ausente no tienen esta regla. La política INPUT sigue siendo drop; la regla no autoriza otras interfaces, familias, protocolos ni puertos.

La adquisición puede recuperarse sin concesión vigente. Por eso no se exige estado conntrack, dirección IP ni vencimiento de concesión. El cliente mantenido valida las transacciones DHCP; el router anunciado no se supone servidor DHCP. No se concede acceso administrativo ni forwarding. Se conservan identidad, época, plazo original y recuperación de concesión/R2, además de procedencia del servicio, inventario de sockets y drenaje de procesos.

El compilador recibe la revisión canónica de red desde el ensamblaje interno autorizado, nunca una interfaz libre ni fragmentos nft del solicitante. La lectura recompila la revisión y rechaza recursos faltantes, alterados o adicionales. Un cambio de red recompila la tabla local incluso con igual revisión local, retirando la admisión anterior durante rollback. La retirada del servicio sigue exigiendo drenaje real y ausencia física; el compilador no gestiona procesos.

Pruebas: `go test -race ./internal/localnft ./internal/routedactivation`; `go vet ./internal/localnft ./internal/routedactivation`; `go build ./internal/previewruntime`; `GOOS=windows GOARCH=amd64 go build ./internal/previewruntime`. Usan compilación pura y el motor real con I/O de kernel/red simulado; no equivalen a DHCP nativo. Se añade una regla/contador por WAN DHCP habilitada, sin proceso, temporizador, conjunto ni persistencia nuevos. Validación y recursos nativos pendientes. Sin cambios Docker, Compose, EKS/Helm ni perfiles instalados.
