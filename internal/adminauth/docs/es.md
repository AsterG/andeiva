# Admisión de acceso administrativo

Alcance experimental: credenciales aleatorias provisionadas de la administración
aislada. [English](../README.md) · [Português](pt.md).

HTTP y SSH usan la IP del socket receptor, sin confiar en cabeceras de forwarding.
Se normaliza IPv4-mapped; se rechazan orígenes ausentes, inválidos, con zona,
indeterminados o multicast. No se implementa delegación de origen por reverse proxy.

Los fallos anónimos comparten un cupo global de cuatro admisiones por segundo y uno
por origen. La tabla fija conserva hasta 128 orígenes, con caducidad perezosa de un
minuto. Los rechazos no prolongan la retención ni expulsan entradas activas. Las
credenciales válidas usan otro cupo de cuatro por segundo y no dependen de la tabla
anónima, incluso llena o detrás de la misma NAT. Se mantienen las 32 sesiones,
caducidad, CSRF, RBAC y auditoría obligatoria. Cada intento de `Login` interno
comparte el cupo anónimo; si la credencial es válida, también consume el cupo
verificado global. Las credenciales inválidas nunca lo consumen. Así no existe
un cupo verificado adicional por esa entrada compatible. HTTP y SSH usan `LoginFrom`.

La clasificación limita usuario a 64 bytes y credencial a 64 caracteres: son 32 bytes
aleatorios, no contraseñas elegidas por el usuario. No reutilizar este almacenamiento
como algoritmo de hashing de contraseñas. No se registran secretos.

Los límites son locales al proceso y se reinician con él. No limitan todos los
handshakes ni garantizan disponibilidad ante cualquier ataque. El préstamo de sesiones
HTTPS por SSH conserva su ruta anterior. La auditoría llena sigue siendo un bloqueo
independiente: un fallo de persistencia obligatoria cierra la autenticación. No hay
rotación, agregación, borrado, cambio de formato ni reglas de tráfico nuevas.

## Pruebas reproducibles

```sh
go test -race -count=1 ./internal/adminauth ./internal/adminapi ./internal/localssh
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
go test -race -count=10 ./internal/adminapi -run '^TestLoginOriginFloodCannotBlockVerifiedHTTPS$'
```

La última prueba requiere Linux, usa TCP real desde `127.0.0.2/3` y TLS con certificado
verificado, sin root ni cambios de red. Los fallos pueden devolver 401/429 según la
ventana real; las cuotas exactas se verifican con reloj controlado. También se prueban
IPv4/IPv6, tabla llena, NAT compartida, cabeceras falsas, concurrencia, sesiones,
auditoría y transporte SSH. El backend y el destino de auditoría son fixtures;
no se aplica nftables ni se modifica el appliance instalado.

La estructura fija mide 7.232 bytes en Linux AMD64 probado; no es RSS ni una garantía
de rendimiento. Los microbenchmarks excluyen transporte y persistencia de auditoría.
La recuperación ante almacenamiento lleno continúa pendiente.
