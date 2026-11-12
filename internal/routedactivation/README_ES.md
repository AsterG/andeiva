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

La activación de la fixture legacy exige tabla schema-4 canónica default-deny realmente conocida, tabla routed
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
tres estados por tabla y batches nft de 512 KiB. La cualificación nativa Debian13
`f6a474f` pasó TCP/UDP SNAT, ICMP relacionado, denegación IPv6 y de conexiones
inversas no solicitadas, revocación de flujos, routing sin NAT y NAT sin permiso
de forwarding. Restauró dos reglas schema4 guardadas, reactivó schema6,
reconcilió una respuesta Confirm perdida y revirtió schema4 al vencer su plazo
original. Limpió los tres namespaces; direcciones, rutas, forwarding y nftables
externos permanecieron intactos. Ensayo completo: aproximadamente45s,
CPU12.890886s, pico cgroup33,546,240bytes con hijos/caché. No es RSS de servicio
ni throughput. El testigo seleccionado es una fixture: no prueba IPC entre
procesos, Boot4 nativo, interfaces principales ni acceso a Internet.

```sh
go test -race ./internal/networkexecutor ./internal/routedactivation -count=3
go vet ./internal/networkexecutor ./internal/routedactivation
```

Boot schema4 sin red usa `Options.ObservedBindings` del inventario autenticado del
supervisor y `PrepareColdBoot(target4, saved4)`. Captura `ObservedSnapshot` sin
plan deseado ni hash de plan, con ausencia real de las tres tablas. Boot/SystemBundle
y el plazo original Started+10s deben quedar seleccionados antes de aplicar.
Apply/rollback schema4 sólo modifica la tabla legacy: no direcciones, rutas,
listeners ni forwarding. La expiración restaura la ausencia real, no la política
Saved prospectiva. Una edición schema4 confirmada puede diferir del Saved original
conservando el baseline observado exacto. La primera activación schema6 compara
todo ese baseline con su PreparedSnapshot real; la inversa schema6→4 sigue
exigiendo el Saved/baseline original autenticado. Un helper nuevo verifica scope
y estado exactos mediante RecoverObserved, sin adoptar namespaces encontrados ni
reiniciar temporizadores. Las pruebas usan compiladores/readback, Group y
coordinador/reservas durables reales con I/O kernel/red simulado. No califican
Boot4 nativo, gestión de interfaces existentes, DHCP ni control del host.
