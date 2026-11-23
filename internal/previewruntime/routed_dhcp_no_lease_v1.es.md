# Adquisición DHCP sin concesión

El servicio puede seguir vivo tras expirar o revocarse una concesión. Su lectura
atómica distingue ese estado de la espera inicial, de una concesión válida y de
un fallo de proceso o canal. La observación sin concesión contiene sólo una época
monótona de revocación y la identidad autenticada de adquisición. No restaura una
concesión, reinicia el motor, amplía plazos ni autoriza reenvío.

Tras retirar y persistir el trabajo seleccionado anterior, `dhcp_begin` puede
devolver un resultado versionado sin efectos. Primero verifica LAN original/WAN
vacía, reenvío desactivado, gate cerrado o ausente, trabajo liberado y runtime
preparado. Otra observación atómica confirma la adquisición; si ya llegó BOUND,
continúa con esa concesión por la ruta normal. Sólo este resultado preefecto
conserva la autorización previa del cliente; nunca la crea. Errores genéricos y
cancelación mantienen sus bloqueos.

Sin concesión, la vista de recursos admite únicamente el perfil acotado de
sockets raw WAN del servicio, sin listeners TCP/UDP. Concesión, R2, época y plazo
siguen controlando L3 y reenvío. La muerte del propietario o un fallo de protocolo
exigen recuperación supervisada; no se adopta otro PID o cgroup. El supervisor y
la contención existentes no cambian.

Las pruebas cubren EXPIRE/BOUND atómicos, pipes privados reales, codec/cliente,
replay de épocas revocadas, cancelación, mensajes mixtos y listeners prohibidos.
Ejecutar `go test -race ./internal/dhcpclient ./internal/firewallipc ./internal/previewruntime -run 'Test(AcquisitionNoLease|RoutedDHCP(NoLease|WaitingV1|InitialWaiting))'`.
Renovación/readquisición nativa, privilegios de la unidad instalada y medición de
recursos siguen pendientes. El cambio de fuente no califica el appliance.
