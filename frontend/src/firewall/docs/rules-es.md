# Administrar reglas ordenadas del firewall

Abra Firewall con una cuenta autorizada. La tabla muestra Borrador local,
Candidata, Activa o De arranque, según la selección. La búsqueda y el filtro de
acción reducen las filas visibles sin cambiar la política.

1. Seleccione Borrador local y Añadir regla, o seleccione un ID para editar.
   Complete origen, destino, protocolo, rangos de puertos y Permitir/Denegar.
   Si el runtime admite el esquema 4, desmarque Habilitada para conservar la regla
   sin evaluar tráfico. Guardar en borrador local no cambia el servidor ni el kernel.
2. Arrastre el control de seis puntos para reordenar. Con teclado: enfoque el
   control, pulse Espacio, elija con flechas o Inicio/Fin y pulse Intro; Escape
   cancela. El menú de la fila permite Mover a la posición. Quite los filtros y
   cierre el editor antes de reordenar.
3. Revise los cambios, prepare la candidata y valídela. Aplicar ahora activa la
   candidata. Aplicar con confirmación añade un plazo: compruebe la conectividad
   antes de confirmar la revisión activa. Si no se confirma, el servidor revierte
   según el contrato transaccional.
4. Revise Ejecución y Al reiniciar. Comparan cada regla visible y su posición.
   El estado de revisión indica si toda la revisión activa está guardada.
   Guardar activa para arranque persiste todas las reglas y su orden.
5. El historial permite restaurar revisiones autorizadas. Tras un fallo, consulte
   el estado efectivo antes de intentar otra operación.

La revisión activa sin guardar puede sobrevivir al reinicio del servicio gracias
al registro persistente. Es distinta de Startup, usada al arrancar el appliance.
Una regla deshabilitada se puede aplicar y guardar; permanece visible y no tiene
contadores de paquetes. Deshabilitar en el borrador no surte efecto hasta aplicar.
Los contadores desconocidos nunca significan tráfico cero.

El tema claro es el predeterminado; el oscuro se selecciona explícitamente. Estos
controles no administran el firewall principal, forwarding, NAT ni interfaces de
administración fuera del despliegue aislado autorizado. Siga la verificación
nativa del despliegue antes de considerar validados el tráfico o la recuperación.
