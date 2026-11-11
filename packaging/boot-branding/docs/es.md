# Identidad de arranque: guía operativa

Este paquete experimental contiene recursos gráficos inactivos. No instala Plymouth, selecciona temas, regenera GRUB/initramfs, renombra entradas ni cambia servicios de red. Una comprobación correcta del paquete no demuestra un arranque correcto.

## Inspección y validación

Ejecutar `bash packaging/boot-branding/tests/run.sh` desde el código fuente como usuario normal de Linux/WSL. Los comandos de construcción e inspección están en el [README](../README.md). Las pruebas no instalan nada ni requieren root. Conservar la procedencia offline firmada y los checksums; un checksum no es una firma.

Antes de cualquier activación futura: comprobar acceso autorizado de recuperación por consola VMware/local, snapshot recuperable, respaldo del arranque, espacio e inodos libres y un kernel/initramfs anterior intacto. Ensayar primero la recuperación. Instalar dependencias de Plymouth puede regenerar initramfs y exige estas mismas comprobaciones. No modificar Secure Boot, particiones, interfaces, rutas ni reglas del firewall por motivos visuales.

## Presentación y diagnóstico

El logotipo original permanece intacto. Los textos propios del tema son siempre ingleses: `Starting system...`, `Restarting...` y `Shutting down...`. La barra indica actividad, sin porcentaje ni afirmación de salud correcta. El idioma y tema web no seleccionan el tema de arranque. Los errores y solicitudes de contraseña externos se conservan; no se garantiza ocultar firmware o fallos tempranos.

Esc, diagnóstico textual, mensajes extensos, solicitudes de cifrado y ausencia de gráficos requieren pruebas reales de consola. Este paquete no añade reinicio Web/CLI. No crear una ruta de shell para aparentar esa integración.

## Actualización, retirada y recuperación

Este incremento no implementa activación ni su reversión. No seleccionar manualmente los recursos antes de aprobar el procedimiento con recuperación. El paquete inactivo solo cambia sus recursos en `/usr/share`. Tras una futura activación, restaurar y verificar el tema/configuración de arranque anterior antes de retirar recursos referenciados por GRUB o initramfs. No eliminar kernels de recuperación ni reemplazar archivos generados.

Consultar [diseño y comprobaciones pendientes](../DESIGN.md). Quedan pendientes renderizado nativo, arranque/reinicio/apagado, actualización del kernel, restauración y mediciones activas. La reversión de paquetes en Debian existente no equivale a recuperación A/B.
