# Gate aislado de autoridad DHCP

Biblioteca experimental para restringir forwarding WAN en un namespace propio,
distinto del host. No está integrada en activación ni recuperación del appliance.
No modifica interfaces, rutas, DNS, firewall ni energía del host. La calificación
nativa de kernel/tráfico y las mediciones de recursos siguen pendientes.

El supervisor confiable entrega descriptores de namespaces, identidad del helper,
plan canónico WAN DHCP/LAN estática y propietario autenticado de la concesión.
El helper conserva sólo NET_ADMIN, no_new_privs y grupos aprobados. El constructor
lee y fija recursos sin mutaciones. Puede coexistir con LeaseExecutor; rechaza
otro gate en el mismo proceso/namespace.

`LeaseGateAuthority.Current` entrega concesión y digest del trabajo seleccionado.
`Verify` debe verificar de manera independiente trabajo/reserva, delta L3, baseline
LAN intacta, política, identidad de interfaces y ausencia de offload. El hash no
autoriza por sí solo. Assembly debe serializar los cambios de autoridad/política.
No se agrega endpoint JSON ni ejecución de comandos arbitrarios.

Secuencia obligatoria:

1. `Initialize` crea cerrada la tabla fija `inet andeiva_lease_gate`, sólo si no
   existe. Nunca adopta ni reemplaza una tabla existente.
2. `Close` elimina apertura y token y verifica la tabla completa. Desactivar y
   comprobar forwarding IPv4/IPv6 del namespace.
3. Aplicar/verificar LeaseExecutor, política y trabajo seleccionado.
4. `Stage` verifica forwarding desactivado y autoridad actual; instala el token
   temporal mientras sigue cerrado. Consume la secuencia antes de escribir.
   Un ACK perdido sólo se resuelve mediante readback, nunca recreando el token.
5. `Open` verifica otra vez y modifica sólo el conjunto de apertura. No recrea
   el token, no extiende su duración ni activa forwarding IP.
6. Una concesión posterior requiere Close y secuencia nueva. Revocación, fallo,
   retirada y Confirm/rollback nunca restauran tokens anteriores.

La cadena forward fija tiene prioridad -300 y DROP en ambas direcciones WAN,
incluidas conexiones establecidas. Descarta IPv6 WAN. No contiene reglas accept,
excepciones conntrack, actualizaciones dinámicas ni flowtables. La política accept
de la cadena base continúa hacia el firewall obligatorio; no lo sustituye.
Assembly debe excluir offload y conservar propiedad exclusiva de escritura.

El parser comprueba tabla, conjuntos, orden y expresiones completos. Rechaza
objetos extra, tokens permanentes, expiración ausente, overflow, claves JSON
duplicadas y cambios semánticos. Muestrea CLOCK_BOOTTIME después de recibir el
readback: segundos restantes más un segundo de redondeo deben vencer antes del
deadline original. Stage reserva dos segundos, pero ese cálculo previo nunca
autoriza Open sin comprobar la duración real después de recibirla.

`ErrLeaseGateUncertain` indica cierre no demostrado: el supervisor independiente
debe desactivar forwarding o destruir su namespace. No anunciar baseline
restaurada ni permitir tráfico. El fallo bloquea la instancia. No hay adopción
tras reinicio, journal nuevo ni recuperación de tokens. La recuperación mediante
trabajo seleccionado/R2 sigue siendo una dependencia separada.

El [contrato JSON](https://manpages.debian.org/trixie/libnftables1/libnftables-json.5.en.html)
usa segundos para timeout; Linux 6.12 [usa jiffies para expiración](https://github.com/torvalds/linux/blob/v6.12/include/net/netfilter/nf_tables.h).
Este corte exige ejecución continua. Suspensión, pausa/restauración de VM y su
comportamiento temporal no están soportados ni demostrados. No cambia energía.

Pruebas sin privilegios Linux/WSL:

```sh
go test -race ./internal/networkexecutor -run '^TestLeaseGate' -count=1
go vet ./internal/networkexecutor
go build ./internal/networkexecutor
go test -c -o lease-gate-native.test ./internal/networkexecutor
```

Las unitarias usan dobles explícitos de kernel. No prueban sintaxis nft nativa,
filtrado de paquetes ni expiración con helper muerto. La futura prueba autorizada
Debian debe reutilizar namespaces/helper aislados y comprobar JSON/unidades reales,
ambas direcciones/conexiones establecidas, pausa/muerte del helper, ACK tardío,
LAN intacta, invariantes dual-stack del host y limpieza. No ejecutar pruebas
privilegiadas en WSL/CI compartido. Sin cambios de servicios Docker/Helm,
dependencias o DTO compartido del coordinador.

## Observación nativa del token del kernel

Tras corregir el protocolo numérico y el orden de declaraciones del readback,
Debian 13 ejecutó `TestNativeLeaseGateKernel` satisfactoriamente (0,18 s). Un
helper con sólo NET_ADMIN instaló L3 WAN real, preparó y abrió el gate y terminó
sin cerrar ni renovar el token. El arnés root observó el token presente tras
la salida y ausente 13 segundos después, mientras `enabled` seguía presente.
Forwarding permaneció en cero; los invariantes del host se comprobaron fuera de
los namespaces.

La autoridad estaba controlada por la prueba. Se acredita expiración observable
sin el proceso helper, no corte de paquetes, instante exacto, SIGKILL/crash,
suspensión, DHCP real, trabajo durable seleccionado ni recuperación productiva.
El namespace aislado limpia la WAN retenida. Exige jq además de las dependencias
del arnés. Ejecutar `ANDEIVA_LEASE_LAB_AUTHORIZED=1 ./lease-native-isolated.sh gate`
sólo en un grupo systemd root limitado del laboratorio autorizado, con PASS
literal y ningún SKIP.

## Calificación de tráfico real preparada

El modo nuevo `gate-traffic` está preparado, sin calificación nativa todavía.
Compilar sin privilegios con
`go test -c -o lease-native.test ./internal/networkexecutor` y comprobar
`bash -n scripts/lease-native-isolated.sh`. Sólo dentro del directorio/cgroup del
laboratorio Debian autorizado, ejecutar
`ANDEIVA_LEASE_LAB_AUTHORIZED=1 ./lease-native-isolated.sh gate-traffic`.
Conservar KillMode=control-group, LimitNOFILE=256 y límite externo de 45 segundos.
El modo agrega timeout de 43 segundos y dos segundos para terminación forzada.

Crea tres namespaces aislados, unidos sólo por veth: gateway, LAN y WAN. El helper
NET_ADMIN existente instala L3 WAN, abre un gate breve y termina. Sólo después
del readback de política/gate se activa forwarding IPv4 en ese namespace;
forwarding IPv6 sigue en cero. La cadena de calificación posterior conserva
aceptación established/related y acepta LAN→WAN sólo TCP18080/UDP18081 exactos.
Input/output siguen DROP.

Servidor/cliente Go usan UID/GID62007, cinco conjuntos de capacidades vacíos,
no_new_privs, pins host/gateway de sólo lectura y direcciones benchmark fijas.
Intercambian nonces nuevos de 32 bytes. El cliente conserva una misma conexión
TCP y socket UDP. Root publica una fase atómica, root y sólo lectura, únicamente
tras observar vacío el conjunto live y enabled aún presente. Después deben vencer
por timeout TCP establecido, UDP y TCP nuevo. EOF, reset, eco distinto o servidor
muerto no acreditan corte. Ambos procesos deben terminar con PASS explícito.

El arnés verifica estructura del gate y política intactas (salvo contadores), uso
de la aceptación established, estado de direcciones LAN e IPv6 cerrado. Desactiva
forwarding IPv4 antes de limpiar, termina y recoge sus hijos; el namespace PID
limita la limpieza ante fallos. El supervisor externo debe comprobar invariantes
dual-stack/mount del host, limpieza del cgroup y CPU/memoria pico. La observación nativa siguiente califica únicamente este modo aislado. No prueba autenticidad DHCP,
trabajo durable, recuperación, suspensión, instante exacto de corte ni paquetes
ya encolados. No activa interfaces host, topología MACVLAN ni forwarding productivo.

### Observación nativa de tráfico al caducar

En Debian 13 AMD64, `gate-traffic` pasó con resultados PASS explícitos del helper,
cliente y servidor aislados. La misma conexión TCP y socket UDP funcionaron antes
de caducar el token del kernel y agotaron su plazo después; se ejercitaron los
contadores established. Direcciones, rutas, reglas, forwarding dual-stack,
nftables y mounts del host permanecieron iguales. El cgroup consumió 0,881 segundos
de CPU y 29.634.560 bytes de memoria pico; el escenario cliente duró 12,66 segundos.
Son observaciones del ensayo, no garantías de capacidad o latencia de corte.
Recuperación DHCP real, selección durable, suspensión e Internet/SNAT requieren
validaciones independientes.

### Retirada terminal después de renovar

Un cambio de concesión cierra el permiso de reenvío anterior y bloquea esa
instancia de forma permanente. La lectura completa puede demostrar el cierre
físico sin rehabilitarla. La retirada exige además reenvío desactivado, el estado
L3 original y la instantánea exacta del trabajo retirado y persistido. Si falla
la liberación de recursos, se conservan las referencias de recuperación y se
impide reconstruir la instancia.

La nueva instancia recupera la secuencia archivada antes de admitir una
concesión seleccionada posterior; nunca recrea el permiso anterior ni amplía su
plazo. Este cambio de fuente no acredita recuperación nativa de renovación,
readquisición tras retirar L3 ni rendimiento. Esas validaciones siguen pendientes.
