# Adaptador autenticado de configuración v2

ServiceV2 reutiliza coordinador y catálogo; sólo abre un almacén preparado. No
migra, activa runtime ni anuncia capacidades. SubjectID y CredentialRevision son
mirrors opcionales inseparables de la cuenta, sujetos al registro canónico. Sin
ambos, la autenticación v1 sigue disponible pero no autoriza v2. No se deriva la
identidad del nombre, credencial, UID ni petición.

El binding opaco exige una sesión real del Manager fijado. Cada operación vuelve
a comprobar logout, plazos, inactividad, rol y mirrors antes del lock de almacén;
registro y acción se verifican bajo ese mismo lock. No se solapan locks de auth y
almacén. Un logout posterior al punto de autenticación no cancela trabajo ya
admitido. Viewer sólo lee estado/proyección; catálogo y cambios requieren admin.
Las respuestas no incluyen revisión de credencial, token ni internals del binding.

[Comandos y límites](SERVICE_V2.md). Pasaron pruebas unitarias/race, revocación
concurrente, propiedad ajena, reapertura y transacciones con motores simulados,
incluida ejecución Debian sin privilegios. No activa servicios del appliance ni
reglas reales. Transporte Web/CLI/API, TLS/CSRF, cutover, pruebas de capacidad
física y proof mapper de servicios locales siguen pendientes. No se elimina
historial protegido ni se afirma una cuota física.
