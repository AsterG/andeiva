# Cargador y supervisor del despliegue agrupado

Este ensamblaje es experimental y la instalación del paquete no lo activa. Las unidades agrupadas no tienen destino de instalación. No habilitarlas antes de completar la migración offline, el aprovisionamiento autenticado de namespaces y las pruebas de recuperación.

El supervisor root sólo lee `/etc/andeiva-preview/grouped.json`. El manifiesto versionado fija el digest de cuentas, cuatro identidades de directorio compartido, tres perfiles de reserva y presupuestos explícitos de lectura/escritura. No contiene políticas ni autoriza su aplicación. El helper verifica independientemente la configuración seleccionada y su integridad completa antes de admitir mutaciones ordinarias.

Los recursos en `/var/lib/andeiva-preview/grouped` y `/run/andeiva-preview/grouped` deben existir con propietarios y permisos exactos. El cargador no crea namespaces, cuentas, políticas ni directorios. Los descriptores deben proceder del gestor confiable y coincidir con la identidad actual de arranque/ejecución. Los namespaces y el journal anteriores se conservan separados. La migración offline debe preservar políticas e historia; una configuración de prueba vacía no es una actualización.

La escucha administrativa se hereda del socket systemd dedicado. Se verifica dirección, interfaz y namespace host antes del lanzamiento; no acepta comodines ni rutas elegidas por el llamador. El socket de salud está separado del directorio de la API anterior. La disponibilidad del listener no implica integridad ni calificación del plano de datos.

La API tiene un presupuesto constante de tres reinicios por minuto, con espera de tres segundos. Un fallo de reinicio o agotar el presupuesto deja la administración degradada y conserva vivos supervisor y helper. El guardian mantiene su plazo original. No hay reinicio automático del helper, borrado del bloqueo de integridad ni eliminación insegura de un socket de salud residual. Puede requerirse recuperación operativa. La parada explícita cierra los hijos; el fallo del helper se informa por separado.

Las pruebas cubren manifiestos estrictos, tipo/identidad del descriptor y agotamiento modelado de reinicios. No califican sandbox systemd, instalación, tráfico real ni despliegue permanente. Las unidades permanecen deshabilitadas hasta superar esas verificaciones.

El `namespace_profile` explícito es `host-gateway-v2`: metadata schema 2 requiere únicamente namespaces host y gateway reales. Este cargador no crea ni acepta namespaces source/sink de pruebas.
