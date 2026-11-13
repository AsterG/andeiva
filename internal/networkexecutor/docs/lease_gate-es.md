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