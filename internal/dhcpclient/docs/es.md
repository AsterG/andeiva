# Adquisición DHCP aislada

Perfil experimental de Debian 13, separado de la API y del helper del firewall.
El supervisor ejecuta dhcpcd con `--noconfigure`; recibir una concesión no autoriza
cambios de direcciones, rutas, DNS ni permisos. Los eventos inválidos, el cierre
del canal, la muerte del propietario o la caducidad invalidan la evidencia.
`RECONFIGURE` revoca sin conceder una nueva concesión. Renovar usa SIGUSR1 y
revincular usa SIGHUP; ambos requieren observaciones posteriores válidas.

## Reproducción

Compilar sin privilegios en Linux con el toolchain del repositorio:

```sh
go test -race ./internal/dhcpclient
go vet ./internal/dhcpclient ./cmd/andeiva-dhcp-hook
go test -c -o dhcp-native.test ./internal/dhcpclient
go build -o andeiva-dhcp-hook ./cmd/andeiva-dhcp-hook
bash -n scripts/dhcp-native-isolated.sh
```

Transferir los dos binarios y el script a un directorio nuevo propiedad de root
en el laboratorio autorizado. Verificar sus SHA-256 antes de ejecutarlos; usar
0755 para el directorio y los binarios, 0700 para el script. Conservar los nombres
anteriores y establecer ese directorio como `WorkingDirectory` de una unidad
transitoria systemd con `Type=oneshot`, `KillMode=control-group`,
`TimeoutStartSec=350`, `TimeoutStopSec=10`, `TasksMax=64` y `MemoryMax=128M`.
La orden de la unidad es:

```sh
/usr/bin/env ANDEIVA_DHCP_LAB_AUTHORIZED=1 /bin/bash ./dhcp-native-isolated.sh
```

Registrar reglas nftables, rutas y forwarding del host antes y después. Consultar
el resultado y el journal de la unidad, y detenerla al terminar. Repetir en una
unidad separada añadiendo `ANDEIVA_DHCP_EARLY_SERVER_DEATH=1` para la negativa de
servidor muerto. Nunca ejecutar la prueba privilegiada en WSL, CI compartido o
un appliance de cliente. El script verifica Debian 13, rechaza CI y valida los
descriptores de los namespaces originales antes de montar rutas privadas.

## Resultados y límites

En Debian 13 con dhcpcd 10.1.0 y BusyBox pasaron adquisición, exclusión de otro
propietario, ACK real de renovación, revinculación, reinicio, caducidad y rechazo
de la concesión guardada sin servidor. El fixture aplica y retira explícitamente
sólo su dirección WAN aislada; conserva la LAN ya configurada. Duración 142,14 s,
CPU 0,445799 s y memoria máxima 19.038.208 bytes. La negativa de servidor muerto
pasó en 35,02 s. No cambió la red del host. Son mediciones de pruebas, no capacidad
del producto. La renovación sin aplicar L3 no superó la prueba.

Esto no implementa adopción de ifupdown, rollback de interfaces principales,
renovación de NAT, continuidad administrativa ni un perfil de privilegios de
producción. Un fallo se contiene deteniendo la unidad y sus descendientes;
no se deben retirar reglas, rutas o archivos ajenos para hacer pasar la prueba.
## Perfil interno V4 de renovación anticipada

`Scope.EarlyRenewalV4` requiere habilitación explícita del supervisor V4 y está
apagado por defecto. Apagado no crea worker, timer ni descriptor exclusivos;
V3 rechaza la opción. No es activación del runtime instalado ni opción de API.

Con D conservador sin modificar, autoridad restante R=D-t, hora del hook válido
g y concesión L: P=(L-28s)/2; I=min(g+P-t, R-22s), sólo si I>=13s. El propietario
aprobó esta fórmula provisional de Alpha el 2026-11-17. Constantes centralizadas
en early_policy_v4.go: adopción 12 s, respuesta 5 s más despacho 1 s, margen de token 3 s
y seguridad 1 s. El timer absoluto BOOTTIME incluye suspensión. Ni g ni SIGUSR1
cambian lastGrant, epoch o autoridad; sólo lo hace un hook válido. Una solicitud
pendiente; un hook espontáneo puede satisfacerla sin atribuir su ACK a la señal.

Tras B2 no se envía solicitud de recuperación cerrada: sólo se espera un grant
espontáneo con autoridad restante suficiente. Mínimo soportado Alpha: 71 s con
T1=floor(L/2) y sobrecoste de respuesta medido inferior a 1 s; siempre se valida
la autoridad restante real. 54 s es sólo el mínimo de calendario, no de continuidad
y recuperación soportadas. Por debajo de 71 s el reenvío permanece cerrado;
la integración del aviso al administrador sigue pendiente.

Despacho tardío, concesión corta, fallo de reloj/señal o falta de evidencia
válida en 5 s revocan la evidencia. El helper existente debe cerrar y verificar
el reenvío (B2); el cliente no modifica ese estado del kernel. Una observación
externa también rechaza respuesta vencida si el worker está demorado. No hay
EXPIRE ficticio ni nueva instancia automática en esta implementación.

Aceptación integrada pendiente: diez renovaciones consecutivas con la misma
conexión TCP y socket UDP. Cada cota superior de corte debe ser<=10s y
hook->Open<=12s; son límites provisionales de esta prueba Alpha, no del producto.
Medir fases, mínimo/mediana/máximo, pérdidas y CPU/memoria/goroutines con/sin B1.

### Medición nativa del componente, 2026-11-17

Dos laboratorios Debian nuevos y aislados, mismo bucle de observación de 55 s
y concesión de 60 s. El proceso medido incluye el componente cliente y el arnés
Go de pruebas; no representa recursos totales del appliance o de su API.

| B1 | Ventana (ns) | CPU proceso (ns) | RSS muestreado máximo (bytes) | Goroutines mín/máx | Renovaciones reales |
| --- | ---: | ---: | ---: | ---: | ---: |
| Apagado | 55000796941 | 436522000 | 9007104 | 6 / 6 | 1 |
| Encendido | 55000182642 | 419576000 | 8978432 | 8 / 9 | 3 |

CPU mediante RUSAGE_SELF, RSS mediante `/proc/self/statm` y goroutines del
runtime Go. Una comparación no demuestra una mejora de CPU/RSS. Ambas unidades
terminaron correctamente; direcciones, rutas, forwarding y namespaces del host
coincidieron con la base tras limpiar. No se midieron supervivencia de sockets
TCP/UDP ni duración del corte en esta prueba del componente.

Repetir con el arnés fijo `scripts/dhcp-native-isolated.sh --early-renewal-off`
y `--early-renewal-on`, en Debian de laboratorio desechable, con artefactos
root y unidad systemd acotada KillMode=control-group. El directorio de trabajo
debe contener `dhcp-native.test` de este paquete y `andeiva-dhcp-hook`.

## Revocación al terminar el productor

La salida del proceso principal revoca inmediatamente la evidencia de concesión
y adquisición, antes de esperar el drenaje de stderr. Un descendiente que retenga
esa tubería no prolonga la autoridad; eventos tardíos y órdenes no la recuperan.
Se conservan la terminación del grupo y la recolección del proceso. Esto no
garantiza un plazo de cierre si el lector del flujo queda bloqueado.

## Cortes medidos en Alpha — 2026-11-17

El propietario aprobó provisionalmente 10s máximos por renovación sólo para esta
prueba del hito Alpha. Una cota superior medida mayor de 10s hace fallar la prueba;
no es un objetivo de producto. Tres cortes en Debian con dos vCPU midieron
7,897–9,406s,7,813–9,336s y 7,654–9,268s. La misma conexión TCP entregó 308/308
mensajes con 15 retransmisiones; el mismo socket UDP envió 1851 datagramas y recibió
943 ecos:908 solicitudes no observadas en destino tras drenaje acotado. Hay
pérdida UDP durante el cierre. Son observaciones de aplicación, no una captura
exacta de todos los paquetes. El ensayo completo FALLÓ 141,15s en la recuperación
posterior de API; no acredita aceptación completa ni habilitación del perfil.

Concesión recomendada para uso operacional de esta Alpha: al menos 1h;120s queda
para estrés de laboratorio. Reduce la frecuencia de cortes; no cambia lo que
asigna el proveedor ni permite rechazar su evidencia válida.

La fórmula provisional aprobada incluye la reserva de adopción medida, sin
ampliar autoridad ni relajar los límites 10 s/12 s. Calificación nativa y comparación
final de recursos pendientes. El handover atómico es obligatorio antes de salir
de Alpha y no se diseña aquí. API y nueva instancia siguen como tareas separadas.
