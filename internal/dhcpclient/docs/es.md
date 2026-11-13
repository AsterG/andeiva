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
