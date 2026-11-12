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

`New(Kernel, Network, localengine.Listeners, Options)` proporciona el motor Group.
Kernel es un transporte confiable del namespace limitado a las tres tablas;
los listeners se observan y retiran exclusivamente dentro del manager propio.
Prepare devuelve `PreparationV1{Before, Target, Dependencies}` sin efectos.
Options.ResolvePlan resuelve esos artefactos desde Intent durable seleccionado y
valida deadline original, referencias contextuales y reservas. La forma o un
resolver que siempre acepta no bastan. `ObserveOwned` y `MatchOwned` sólo devuelven
o verifican referencias seleccionadas después del readback semántico físico.

El arranque exige tabla schema-4 canónica default-deny realmente conocida, tabla routed
ausente, IPv4 vacío y tabla local ausente o vacía conocida. Una transacción nft
instala deny routed/local y retira legacy antes de configurar rutas. El target
sustituye deny después de verificar red y listeners propios. La recuperación
instala deny, restaura o retira listeners propios, restaura el memento de red y
restablece tablas previas atómicamente, incluida ausencia comprobada. Estado ajeno
o desconocido bloquea en vez de borrarse a ciegas. Se exigen escritores exclusivos;
no hay atomicidad frente a CAP_NET_ADMIN ajeno. Ediciones posteriores exigen el
mismo plan de red.

El supervisor provisiona la revisión schema-4 seleccionada exacta, incluidas sus
reglas, exclusivamente dentro del namespace nuevo propio con IPv4 vacío. Readback
semántico rechaza reglas omitidas aunque el comentario anuncie el hash esperado.
No se resetea a política vacía ni se adopta una tabla encontrada.

La inversión 6→4 exige Options.ResolveBaseline desde el Work frío original:
bundle guardado, BeforeOwned físico y dependencias. La referencia durable de un
salto conserva lineage y encarnación del manager. Se comparan revisiones exactas
firewall/local y snapshot completo; ausencia local no sustituye listeners guardados
habilitados. Una lease confirmada mantiene deny durante retiro de listeners/red;
legacy sustituye routed atómicamente. Expiry repone red/listeners/reglas schema-6
anteriores bajo deny. El baseline confirmado puede activar nuevamente el mismo
plan. Prepare usa el lado físico before/target real tras recover, sin selector
optimista del último target.

`RecoverPlan`, exclusivo del arranque confiable del helper, resuelve el Work
original autenticado y llama RecoverPrepared con UID/GID/boot/run/namespace
target/host exactos. Root verifica lineage/generation, Intent seleccionado,
finality y lease/deadline originales antes de devolver artefactos. Sólo admite
la misma encarnación retenida y baseline o target completo tras dos observaciones
de red. Estado mixto/ajeno bloquea sin borrar. No arma otro timer ni decide
revertir operaciones confirmadas. Reboot u otro namespace exige Boot controlado,
sin reutilizar autoridad de ifindexes previos.

No se habilita runtime ni se proporcionan pruebas de endpoints, recuperación
durable o adopción del manager del host. El ensamblaje autentica metadata y FDs.
Reiniciar el helper no reconstruye propiedad del ejecutor desde el snapshot.
No se agregan base de datos, workers ni procesos: se usa una lease Group, hasta
tres estados por tabla y batches nft de 512 KiB. Las pruebas controladas ejercitan
compiladores y fallos. La fuente exacta `3918ad8` pasó tráfico/Confirm/expiry/recovery
nativos en tres namespaces: wall 46.166222 s, CPU 13.259767 s y pico 31,281,152 bytes.
No atribuir esa medición a la extensión posterior inverse/reglas legacy, reinicio
de helper, recuperación tras crash o continuidad de endpoints, aún sin cualificar.

```sh
go test -race ./internal/networkexecutor ./internal/routedactivation -count=3
go vet ./internal/networkexecutor ./internal/routedactivation
```
