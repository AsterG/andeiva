# Observación conjunta nueva en cada llamada

El adaptador experimental obtiene la revisión actual y la referencia del estado
controlado de una observación semántica completa bajo el mismo lock del motor.
Las cuatro fases de verificación al abrir DHCP siguen siendo independientes.
No se reutilizan resultados entre fases ni RPC. El camino común pasa de ocho
a cuatro observaciones completas; el fallback contextual Before/Target puede
necesitar más lecturas y vuelve a validar la pareja después de comprobarlo.

La entrada RPC exige la interfaz opcional conjunta, propaga el contexto restante
y permite cancelar la espera de los locks Group/Engine. Current legado conserva
su segundo de presupuesto. No se amplían los plazos de concesión, confirmación
ni RPC de tres segundos. La deriva física y los efectos inciertos bloquean el
acceso. No se garantiza interrumpir cualquier I/O de disco/kernel; se conserva
la contención del supervisor. Rendimiento nativo tras reinicio pendiente. No
se crean procesos, listeners, workers, datos persistentes ni API pública, y no
se modifican unidades de despliegue.
