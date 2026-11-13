# Ensamblaje del gateway administrado

El launcher nativo posee un namespace nuevo y dos interfaces hijas privadas.
Las interfaces físicas se vinculan por índice, nombre, MAC y MTU. Una identidad
local del nodo conserva las MAC hijas entre RunID; no es una credencial ni una
política compartida. Nunca se adoptan namespaces existentes.

Sólo se levantan o eliminan interfaces hijas identificadas positivamente. El
launcher no establece direcciones, rutas, NAT ni forwarding. IPv6 y forwarding
se cierran antes de crear interfaces. Los efectos L3 y su comprobación siguen
siendo responsabilidad del motor transaccional. La API permanece en administración.

Un registro root de cutover vincula los manifiestos operativos y de interfaces.
No sustituye G1: deben pasar la configuración seleccionada y el readback
independiente del helper. El namespace se elimina después de recoger los hijos
del supervisor. Los archivos desconocidos impiden limpiar o reiniciar; no se
borran. Instalar el paquete no crea la activación ni habilita el servicio agrupado
incompleto.

Las pruebas cubren vínculos, hashes, sustitución de interfaces, cancelación,
acuse perdido y limpieza idempotente. El ciclo instalado, cutover frío, arranque
DHCP y acceso del cliente a Internet requieren validaciones independientes.

El comando opcional de preparación root `andeiva-preview grouped-retirement-slot` preasigna un recibo de retiro de tamaño fijo de4096bytes. La unidad agrupada sólo puede escribir ese archivo. Antes de emitirlo, la parada normal debe observar únicamente el PID supervisor en el cgroup dedicado sin delegación y después liberar el namespace propio exacto. Descendientes, timeout, archivos desconocidos o limpieza incierta impiden el recibo y conservan evidencia de recuperación. No garantiza recuperación ante SIGKILL ni cortes de energía. Las pruebas del archivo y del drenaje real de procesos son gates distintos; el consumidor no debe activarse antes de aprobar ambos.
