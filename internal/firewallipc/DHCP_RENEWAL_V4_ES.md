# Transporte de renovación DHCP idéntica

Los pares de confianza negocian explícitamente `routed_dhcp_same_effective.v4`,
además de DHCP seleccionado, inventario e integridad. El cliente antiguo no puede
enviar `dhcp_renew`; la petición sólo contiene hashes de Work y snapshot. La
respuesta contiene la concesión autenticada o un error de recuperación. El
transporte no valida por sí mismo la igualdad L3 ni activa la renovación.
El helper antiguo rechaza la capacidad y el verbo nuevos hasta disponer de
soporte runtime equivalente; no confirma una negociación que no pueda cumplir.

Sólo este perfil permite diez segundos en apply/open/withdraw/retire/renew. Los
clientes antiguos y las lecturas mantienen tres segundos; contextos más cortos
y cancelación limitan la espera del cliente. Un timeout no demuestra ausencia de
efectos ni compensación terminada. La incertidumbre invalida el canal. No cambia
plazos de lease, Confirm o recuperación ni añade procesos, sockets o almacenes.

Reproducir: `go test -race ./internal/firewallipc` y
`go vet ./internal/firewallipc`. Incluye negociación y plazos con conexiones
reales en memoria y reloj virtual. No califica renovación nativa ni rendimiento.
