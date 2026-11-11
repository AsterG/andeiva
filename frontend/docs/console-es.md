# Consola administrativa

Antes de autenticarte solo se muestra la pantalla de acceso, el logotipo original
y los selectores de idioma y tema. Los menús y las vistas administrativas se
montan tras validar una sesión vigente; se retiran al cerrar sesión, caducar o
recibir un rechazo de sesión. Este límite de presentación complementa la
autorización del servidor y no sustituye la autenticación ni el RBAC de la API.

Abre la dirección HTTPS del appliance para entrar en la consola autenticada.
`/firewall` sigue disponible. La navegación usa `#dashboard`, `#rules`, `#audit`,
`#configuration` y `#traffic`; cambiar de vista no crea otra sesión ni prepara
configuración. Los ejemplos de componentes están separados en
`/?view=design-system` y no representan el estado del appliance.

El panel general calcula las reglas desde Running y los totales de paquetes y
bytes desde la última revisión efectiva verificada. Son observaciones, no tasas
ni conexiones individuales. GeoIP, tasas RX/TX por interfaz, CPU y memoria quedan
no disponibles si la API no proporciona esas observaciones. El mapa es geografía
estática, sin flujos ni clasificaciones de países inventados.

El editor lateral admite IPv4, TCP/UDP, rangos inclusivos de puertos de origen y
destino, Permitir/Denegar y habilitación según las capacidades anunciadas. Los
objetos reutilizables, grupos FQDN e identificación de aplicaciones aún no están
disponibles. Cambiar de vista conserva el formulario y borrador local; cerrar la
sesión o caducar la sesión los elimina. Se puede ordenar con mouse, control táctil,
teclado o posición explícita. Los filtros y el editor abierto impiden una
reordenación ambigua.

Preparar publica el borrador como Candidate. Validar comprueba Candidate; aplicar
con confirmación modifica Running y programa la reversión si no se confirma.
Guardar conserva toda Running en Startup para el próximo arranque del sistema.
Reiniciar un servicio no equivale a reiniciar el sistema. El menú de acciones
contiene el plazo de confirmación, Commit inmediato, descarte del borrador local
y detalles técnicos. Descartar no elimina Candidate persistida.

Auditoría requiere administrador. Los filtros se limitan a la página cargada.
Las fechas usan el calendario local del navegador, como las marcas de tiempo
visibles. El detalle muestra actor, cliente, resultado y revisión completa.
Expande las revisiones confirmadas para solicitar rollback. Configuración compara
el orden y los campos efectivos de Candidate, Running y Startup.

Light es predeterminado; Dark se elige y guarda explícitamente. Hay EN/ES/PT y el
logo aprobado se conserva. Las pruebas del navegador usan respuestas de prueba;
no demuestran autorización real ni aplicación de reglas. Antes de desplegar se
requiere validación nativa en Debian autorizado.

Desde `frontend`, ejecuta `npm run lint`, `npm test` y `npm run build`. Desde la
raíz: `docker build -f frontend/Dockerfile.visual -t andeiva-console-check .` y
`docker run --rm --network none --shm-size 256m andeiva-console-check`.

Los campos de dirección y puertos del editor asocian individualmente su ayuda y sus errores para tecnologías de asistencia. Durante un arrastre se bloquean las columnas, filtros, selección de revisión y posición explícita hasta colocar o cancelar. Escape cancela el movimiento; el cambio sigue siendo local hasta preparar la candidata.

## Editor de reglas movible

En escritorio el editor se abre como una ventana amplia y centrada. Arrastra su
cabecera o utiliza Mover ventana con las flechas (Mayús para un paso más fino),
Inicio para centrar y Entrar para terminar. Escape cancela el movimiento; otro
Escape cierra el editor. Centrar ventana restaura su posición. Puedes consultar
la tabla del fondo; las escrituras de configuración y la actualización de estado
quedan bloqueadas mientras editas. Salir de Reglas conserva el formulario y
muestra un enlace de regreso en las demás vistas.

En pantallas pequeñas ocupa el viewport y mantiene el foco de teclado dentro.
Cerrar o cancelar descarta el formulario actual; conservar una regla en el
borrador local no la prepara ni aplica. ID de regla sigue siendo su identificador
técnico, no una descripción libre. Objetos y otros protocolos siguen separados.
