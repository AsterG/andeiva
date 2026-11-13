# Lector privado de selección

Root lanza un lector fijo sin capacidades, con la identidad helper y el grupo
lector. Hereda cuatro directorios de solo lectura y dos pipes privados. PID e
inicio de padre/hijo y un nonce nuevo vinculan la respuesta acotada. Una lectura
fallida no publica un resultado válido.

Retirement lee CURRENT e historia completa mediante ObserveRetirementSourceV3.
DHCP resuelve el trabajo seleccionado y su bundle DHCP canónico, y revalida la
referencia. Ningún resultado concede autoridad por sí mismo: root conserva la
barrera de publicación hasta terminar el efecto. No se admiten rutas, identidad,
ejecutable ni leases en caché enviados por API.

Pruebas unitarias cubren proceso, codec y almacenamiento seleccionado real con
I/O físico simulado. Otra prueba nativa Debian 13 ejecuta el lector sin capacidades
después de bootstrap, readback y reinicio API conservando helper. Tras salir el
escritor, root retiene su checkpoint lock original: admite selección actual y
rechaza un ámbito ajeno. No demuestra retirada del namespace, preparación DHCP
ni la barrera de publicación del DHCP en vivo.

Usar las condiciones de aislamiento de [la guía nativa](routed-launch-native-v3.es.md)
y el modo `--isolated-selected-preflight-lab` de
`packaging/preview/tests/routed-launch-native.sh`. Exigir PASS de
`TestNativeRoutedSelectedPreflightV4` y `ANDEIVA_NATIVE_LAUNCH_CLEANUP_OK`; SKIP
no es evidencia. Comparar direcciones, rutas, reglas y forwarding del host.
Una ejecución duró 1,76 s; el arnés completo consumió 1,883 s de CPU y un pico de
36,7 MiB. Son mediciones de prueba, no presupuestos del servicio permanente.
