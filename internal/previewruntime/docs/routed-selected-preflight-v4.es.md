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
I/O físico simulado. Faltan lanzamiento root y ciclo nativo; este lector no
demuestra retirada del namespace ni preparación DHCP.
