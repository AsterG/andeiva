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
