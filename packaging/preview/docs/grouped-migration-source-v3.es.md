# Inspección del origen para migración offline

El instalador debe detener la API anterior y su socket conservando helper y gestor de namespaces. El núcleo mantiene ambos locks de origen hasta publicar la selección. El callback no sustituye esos locks ni los fingerprints exactos.

Dos roles fijos inspeccionan el origen: la identidad API sin capacidades ejecuta únicamente state/observe/state contra el helper autenticado; la identidad helper con sólo NET_ADMIN entra al gateway anterior fijado por descriptor y verifica semánticamente la política completa. Las tablas locales y routed administradas deben estar realmente ausentes. El perfil inicial exige cero declaraciones de servicios locales; no atribuye listeners ajenos a ANDEIVA.

El padre consulta el guardian antes y después de inspeccionar el kernel. Ambas consultas exigen idle, mismo PID real del helper y recibo idéntico. Conserva ID, destino y plazo históricos; no los reinicia. Ningún rol ejecuta Recovered, Apply, Arm ni Confirm. El handshake de lectura avanza la época del controlador anterior; reiniciar esa API conserva su recuperación normal.

Solicitudes limitadas a 64 KiB y respuestas a 4096 bytes. Roles fijos con FD3 de namespace heredado, pipes de root, comprobación del padre y señal al morir éste. No acepta ejecutables, rutas de namespace ni comandos del llamador. Errores de lectura, cambio de helper, fase no idle, política o recibo distintos rechazan la migración.

Pruebas con kernel simulado, compilador y verificación semántica reales y respuestas del guardian modeladas. No acreditan ejecución entre identidades, instalación ni kernel real. El despliegue permanente permanece deshabilitado hasta superar migración completa, arranque y recuperación.
