# Enlaces propios del gateway

El supervisor root puede crear dos hijos MACVLAN de modo privado directamente en
un namespace gateway fijado y de propiedad exclusiva. Valida índice, nombre, MAC
y MTU de cada padre mediante lectura actual. No mueve ni reconfigura padres.
Las MAC hijas derivan de la identidad de ejecución. Los hijos quedan abajo y sin
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