# Componente de servidor confinado

Experimental y desactivado por defecto. Sin API, dispatcher productivo ni nueva
base de configuración. Reutiliza controles del supervisor existente. Root debe
proporcionar un proceso dedicado dentro del gateway y un namespace de montajes
privado, FDs auténticos, configuración compilada RO, directorio persistente de
`_kea`, presupuesto de almacenamiento y contexto acotado.

Los tmpfs privados cubren `/run`, `/var/lib` y `/etc/kea` antes de crear directorios.
La configuración aparece RO en `/etc/kea/kea-dhcp4.conf`; el directorio persistente
se monta en `/var/lib/kea`. La ruta fija es `/var/lib/kea/kea-leases4.csv`. No se
modifica AppArmor ni se restauran leases desde revisiones administrativas.
El servidor recibe únicamente NET_RAW/BIND_SERVICE; el validador `kea-lfc` no
recibe capacidades. Ambos usan `_kea`, perfiles stock y argumentos fijos.

Configuración exacta root:`_kea` 0440, nunca legible por todos. Padres privados
0750 root:`_kea`; directorios del motor 0700. El modo de `/run/lock` se aplica y
verifica mediante FD tras crear 0700, conservando recorrido del grupo con umask 077.
El pidfd se obtiene atómicamente con `SysProcAttr.PidFD` antes de Wait; no se busca
un PID que ya pudo reutilizarse. Sin soporte kernel se aborta antes de reap.

Se rechazan archivos desconocidos, enlaces, ACLs, permisos/propietarios incorrectos,
PID de LFC y exceso del presupuesto. Root debe excluir otros escritores y mantener
enmascarado el servicio stock. El flock no reemplaza esa propiedad exclusiva ni
una cuota de disco. Todos los FDs heredados quedan CLOEXEC antes de ejecutar.

Kea `-T` fuerza `persist=false`: no valida historial memfile. `kea-lfc -4 -d`
comprueba copias privadas de cada archivo permitido; se exigen exit0, estadísticas
únicas de lectura/escritura sin errores, terminación y ausencia de advertencias,
errores o truncamiento. El resultado nunca reemplaza originales. Hashes verifican
que lo inspeccionado no cambió; no son autenticación. No se promete inmunidad
frente a corrupción semántica arbitraria o Root comprometido.

Cancelación: SIGTERM, luego SIGKILL tras el presupuesto existente de cinco segundos,
Wait y drenaje de descendientes. El rol dedicado debe salir para liberar montajes;
Root verifica después el cgroup completo. Se conservan los leases.

Stdout/stderr del servidor son los `*os.File` heredados directamente, sin copier,
cola ni cuota interna. Root acota tasa, retención y almacenamiento del journal/unidad
externos. La captura LFC sigue acotada en RAM sin otro writer. La negativa con pipe
real llena cancela y completa Wait/reap sin leer stdout bloqueado.

Entrada nativa: `go test -c -o server-native.test ./internal/previewruntime`, test
`TestNativeRoutedDHCPServerV1`; variable `ANDEIVA_DHCP_SERVER_NATIVE_V1=serve|corrupt`.
Sólo Debian13 aislado, nunca WSL/CI. FD3/4/5 fijan NET/MNT/PID del host; `/run/andeiva-kea-fixture`
privado root0700 contiene `leases` de `_kea`0700. Cada ejecución usa montajes y proc
privados dentro del cgroup agrupado fijo. LAN: `lan0`198.18.1.1/24, concesión única
198.18.1.100, duración120, T1/T2 60/105, subnetID17, sin DNS/NTP.

Root mantiene clientes aislados hasta `prepared.json` con observación real de
proceso/caps/NNP/AppArmor/namespace/socket RAW; esto no autoriza política. Reutiliza
el cliente dhcpcd revisado para BOUND/RENEW, interfaz no habilitada, parada SIGTERM,
reinicio con el mismo directorio y rechazo de fila corrupta preservando bytes.
Archiva el marcador anterior antes del reinicio. El timeout120s sin SIGTERM falla.
Forwarding0 no bloquea por sí mismo DHCP RAW; no se inventa ese gate.

Pruebas locales no acreditan DORA, persistencia, transición LFC de AppArmor ni
rendimiento productivo. Mediciones nativas y revisión independiente pendientes.
Comandos locales y procedimiento completo: [English](../runtime.md). Docker/EKS
y contratos compartidos permanecen intactos.

Montar tmpfs privado en `/run` antes de crear este destino. El test conserva su FD de directorio antes de que el componente vuelva a superponer `/run`.

En el fixture veth, los peers permanecen UP sólo para proporcionar el carrier requerido por Kea. Antes de la observación preparada, sus namespaces no tienen procesos, direcciones de endpoint ni clientes. Después se inicia únicamente el cliente revisado. Este aislamiento no constituye un gate RAW del producto.

El destino stock `/etc/kea` puede ser `_kea:_kea` con modo exacto0750. Se abre desde `/etc` validado y propiedad root, sin symlinks, y se conserva mediante FD para superponer el tmpfs privado. Su contenido original nunca aporta configuración. Los demás padres siguen siendo root; se rechazan propietarios desconocidos, grupo stock distinto, escritura para grupo/otros y ACL.
