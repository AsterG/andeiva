# Enlaces propios del gateway

El supervisor root puede crear dos hijos MACVLAN de modo privado directamente en
un namespace gateway fijado y de propiedad exclusiva. Valida índice, nombre, MAC
y MTU de cada padre mediante lectura actual. No mueve ni reconfigura padres.
Las MAC hijas derivan de una identidad persistente local del nodo. Los hijos quedan abajo y sin
direcciones: L3, forwarding y activación corresponden al ejecutor transaccional.

El gateway debe contener sólo loopback. Cambios inesperados del padre, enlaces
ajenos o confirmación incierta bloquean nuevas creaciones. La limpieza elimina
únicamente identidades observadas después de su creación; no borra reemplazos
por coincidencia de nombre. Los restos inciertos requieren destruir el namespace
propio del supervisor. No adopta enlaces ni implementa recuperación entre
procesos. El supervisor conserva los descriptores hasta terminar la limpieza.

Las pruebas sin privilegios cubren ciclo de vida, cancelación, enlaces ajenos,
cambios del padre, reemplazos y confirmaciones inciertas. El script optativo
`scripts/routed-links-native-isolated.sh` prueba el mecanismo real con padres
dummy en namespaces privados de red/montaje/PID. Exige Debian 13 descartable y
un grupo systemd root limitado; nunca un runner compartido. No acredita NIC
física, DHCP, forwarding ni instalación del producto.
El productor root crea además un pin gateway nuevo, sin adopción, en un directorio
vacío root:root 0700. Los montajes usan el FD retenido del directorio. Unshare se
ejecuta en un hilo exclusivo fijado; si falla la restauración, ese hilo se retira.
Operaciones fijas nsenter/sysctl configuran sólo el namespace nuevo y verifican
forwarding apagado e IPv6 deshabilitado antes de retornar. La limpieza registra
por separado detach y eliminación para reintentar interrupciones sin borrar un
reemplazo. El arnés nativo inyecta ambas interrupciones y exige reintento correcto
y directorio vacío. MNT_DETACH no acredita drenaje de procesos: el supervisor debe
parar su cgroup antes de liberar el namespace. La integración/activación requiere
gates separados; estos constructores no habilitan servicios instalados.