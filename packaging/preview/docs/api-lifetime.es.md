# Ciclo de vida de administración

El target requiere el gestor de namespaces y el helper, pero sólo solicita el socket HTTPS y la API mediante Wants. Detener o fallar la API/socket conserva las reglas aplicadas, el gestor de namespaces y el plazo independiente del helper. La parada explícita del target y los fallos del helper/namespaces mantienen su cierre coordinado. Los límites de reinicio de la API siguen vigentes; la administración puede quedar degradada sin eliminar el plano de datos.

Validación: `bash packaging/preview/tests/api-lifetime-unit-graph.sh`. Comprueba dependencias, no tráfico ni fallos reales de systemd; requieren pruebas aisladas en Debian.
