# Calificación nativa aislada de LeaseExecutor

Prueba optativa para laboratorio Debian 13 autorizado y descartable; no activa
el appliance. No modifica interfaces, IP, rutas, DNS ni forwarding del host.
Exige servicio systemd acotado con `KillMode=control-group`,
`RuntimeMaxSec=120s`, `TimeoutStopSec=10s` y `LimitNOFILE=256`. Nunca ejecutar red
privilegiada en WSL, CI o appliances de clientes. Ejecución nativa, revisión
independiente y medición de recursos de este fixture están pendientes.

Compilar sin privilegios:

```sh
go test -c -o lease-native.test ./internal/networkexecutor
bash -n scripts/lease-native-isolated.sh
sha256sum lease-native.test scripts/lease-native-isolated.sh
```

Transferir ambos archivos a un directorio nuevo propiedad de root; verificar
hashes y usar archivos regulares de un enlace, propiedad root y modo `0555`.
El supervisor necesita `ip`, `nft`, `unshare`, `mount`, `setpriv`, `cmp` y Bash
estándar de Debian. No inicia daemon ni servidor DHCP. Dentro del servicio,
usar ese directorio de trabajo e invocar:

```sh
ANDEIVA_LEASE_LAB_AUTHORIZED=1 ./lease-native-isolated.sh
```

El harness valida descriptores originales y namespaces privados mount/net/pid
antes de montar. Rechaza entrada directa sin descriptores o con namespace actual
igual al host. Un `/run` privado contiene binario y namespace peer. Dos pares
veth sin conexión con interfaces host forman LAN/WAN: LAN `198.18.0.1/24`, WAN
vacía. Forwarding IPv4/IPv6 cero y tres cadenas inet con política drop.

Un proceso UID/GID 62006 sin capacidades debe rechazar el constructor sin
efectos. Otro, con sólo NET_ADMIN en los cinco conjuntos y no_new_privs=1, usa
constructor y lecturas reales del kernel: concesión, replay, renovación del
mismo tuple, cambio de dirección, revocación, expiración CLOCK_BOOTTIME y retiro.
Un tercer proceso debe rechazar WAN ocupada mientras el propietario original
conserva su estado. La negativa final revoca autoridad después de la última
lectura real; no sustituye bytes del transporte. La compensación debe restaurar
LAN/WAN vacía exactas. Verifica descriptores de sólo lectura, identidad,
forwarding cerrado y firewall inalterado.

Los hechos del lease provienen de un callback del test: acredita realización L3,
no protocolo DHCP, IPC autenticado, propiedad persistente, expiración autónoma,
forwarding ni administración accesible. La evidencia DHCP previa es separada.
Registrar hashes, resultado completo, CPU/memoria pico del cgroup y ausencia de
descendientes/namespaces tras detenerlo. El supervisor externo debe comparar
links, direcciones, rutas, reglas, nftables y forwarding del host antes/después,
también ante fallo o parada forzada. Un PASS no prueba por sí solo esos
invariantes ni limpieza completa. No relajar controles para hacer pasar el test.
