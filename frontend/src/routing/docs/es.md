# Configuración enrutada

La consola utiliza la capacidad autenticada de configuración v2. Instalar el
frontend no migra el almacén ni activa motores. El editor actual admite dos
interfaces estáticas; rechaza sobrescribir topologías mayores o configuradas por
DHCP. NAT de origen necesita una regla Permitir independiente.

Los cambios locales no afectan al tráfico. Preparar crea la candidata; Validar
comprueba sus datos. Aplicar requiere confirmación en 30–120 segundos. Confirmar
utiliza la operación original y la revisión compuesta. Guardar conserva toda
Running para el reinicio; restaurar Startup también requiere confirmación.

El orden es global y first-match: borre la búsqueda antes de arrastrar reglas.
Con teclado: Espacio, flechas, Intro y Escape. Las reglas deshabilitadas permanecen
configuradas y no evalúan tráfico.

Un resultado incierto bloquea nuevas escrituras. Consulte el ID conservado antes
de actuar; ejecutar de nuevo sólo se ofrece explícitamente para una solicitud
aceptada. No hay reejecución automática ni sustitución por escrituras v1.
Una revisión seleccionada no demuestra aplicación: el estado efectivo necesita
observación del kernel coincidente con su generación y revisión.

Las pruebas de navegador utilizan respuestas ficticias identificadas en sus
fixtures. Cubren EN/ES/PT, Light/Dark, teclado, accesibilidad y diseño responsive.
No prueban el tráfico ni sustituyen la validación nativa. Los comandos de
reproducción están en [README](../README.md).

La auditoría protegida requiere administrador. Sus filtros se combinan sobre la
página cargada. La consulta tiene límites de 1024 registros y 2 MiB e informa si
queda incompleta. Los nombres proceden del registro actual; el ID del actor es
duradero. No se inventa el origen Web/CLI/API de registros históricos sin esa
procedencia, ni se presentan cambios de configuración como eventos de tráfico.

Las reglas schema4 conservadas reutilizan la tabla y el editor, sin inventar un
plan de red. Reemplazar o descartar una candidata exige revisión, ID de Stage
anterior y generación exactos. Stage nunca reemplaza una candidata existente.
El servidor verifica su propietario duradero. Estas operaciones no aplican cambios
al tráfico. Las bases históricas siguen visibles; Validar y Commit permanecen
bloqueados hasta un reemplazo explícito.
# Configuración DHCP LAN

La sección Red permite editar ámbitos DHCP sólo para LAN estáticas seleccionadas.
Los cambios entran al mismo borrador local y utilizan Preparar, Validar, Aplicar
con confirmación, Confirmar y Guardar. Deshabilitar conserva todos los ajustes.
La versión 1 de política sin cambios mantiene sus bytes; añadir DHCP utiliza
la versión 2 con `dhcp_server`. No existe un almacén ni una API adicional.

Se validan rangos, exclusiones, reservas, DNS/NTP, dominio y concesión/T1/T2,
también con DHCP deshabilitado. Cambiar una red que invalide un ámbito se rechaza;
actualice o elimine primero ese ámbito. El servidor conserva la autoridad final.
Habilitado en configuración no acredita servicio activo ni concesiones asignadas.
Los errores del servidor se muestran sin inventar telemetría ni activar WAN.

Pruebas: `npm test`, `npm run build`,
`npx playwright test dhcp-settings.spec.ts routing.spec.ts`. Las pruebas de
navegador utilizan fixtures explícitos EN/ES/PT, Light/Dark y tres tamaños;
no demuestran DHCP nativo. Revertir el frontend no autoriza degradar datos v2 a v1.

Para editar: Red → Añadir ámbito, seleccione la LAN estática, indique ID y rango
utilizable, complete las opciones y temporizadores y conserve el borrador local.
Habilite con la casilla explícita y revise Preparar cambios. Validar y Aplicar
pueden rechazar una configuración sin soporte de ejecución. Confirme el acceso
tras aplicar antes de Guardar para reiniciar. Esto no prueba concesiones DHCP.

Validación 2026-11-14: lint/typecheck, 71 tests unitarios y build Docker aprobados;
72 tests de navegador DHCP/routing con fixtures, EN/ES/PT y Light/Dark aprobados.
Capturas revisadas en escritorio y móvil; ninguna violación Axe en el alcance
comprobado. No certifica accesibilidad completa ni ejecución DHCP nativa.
Incremento gzip: JavaScript 4,91 kB; CSS 0,07 kB. CPU/RAM sostenidos pendientes;
sin dependencias, sondeo periódico, procesos nuevos ni cambios EKS/Helm.

Durante la edición de un ámbito se bloquean actualizar, descartar y las acciones
transaccionales. Si cambia el borrador o la respuesta de configuración de origen,
se cierra el editor antes de guardar. También se invalida al perder permisos,
bloquear escrituras, salir de Red o cerrar sesión. Las ediciones ya conservadas
en el borrador compartido permanecen; el formulario sin guardar no se traslada
a otra generación o posición del ámbito. Las pruebas incluyen 24 casos de
invalidación y el flujo completo de actualización, descarte, navegación y sesión.
