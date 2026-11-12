# Artefactos de activación enrutada

`OwnedV1` conserva el snapshot IPv4 preparado y la presencia explícita de las
tablas fijas legacy, routed y local. Una tabla presente exige revisión canónica
completa de esquema 4, 6 y 3, respectivamente; una ausente exige revisión nil.
La ausencia local sólo comprende listeners propios de este manager y namespace;
no describe ni modifica SSH, HTTPS o listeners del host o de otros managers.

`DependenciesV1` vincula el plan completo con enlaces observados, inventario local
y vecinos confiables. Los objetos canónicos son copias independientes de hasta
256 KiB. `PreparedSnapshot` conserva identidad, MTU, flags, direcciones y rutas
IPv4 observadas en hasta 16 KiB. El perfil inicial admite dos enlaces planificados
y loopback opcional, con IPv4 inicialmente vacío. Rechaza recursos ajenos, DHCP
y baselines configurados arbitrarios.

Prepare y VerifyPrepared sólo leen. ApplyPrepared compara el baseline completo
antes de efectos. RestorePrepared sólo retira adiciones registradas por la misma
instancia y verifica restauración exacta con contexto independiente y acotado.
Ni el snapshot ni su hash conceden propiedad. Un ifindex sólo es testigo local;
no autoriza adoptar enlaces después de reiniciar.

Estos artefactos aún no proporcionan activación física del grupo, recuperación
durable, pruebas de endpoints ni habilitación runtime. El ensamblaje autentica
metadata y descriptores retenidos; el coordinador valida Intent seleccionado,
contexto de objetos y reservas antes de efectos. No se agrega otra base de datos.

```sh
go test -race ./internal/networkexecutor ./internal/routedactivation -count=3
go vet ./internal/networkexecutor ./internal/routedactivation
```
