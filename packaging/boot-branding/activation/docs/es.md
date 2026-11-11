# Activación local del arranque — experimental

Solo para el operador de plataforma autorizado en consola local. No es una API web, instalador ni mecanismo de actualización firmado. Las pruebas con archivos aislados no acreditan activación, gráficos o recuperación nativos. No ejecutar en Windows.

Construir y probar como usuario normal Linux/WSL con Go del repositorio:

```sh
go test -race ./packaging/boot-branding/activation
go vet ./packaging/boot-branding/activation
go build -trimpath -buildvcs=false -o /tmp/andeiva-boot-activation ./packaging/boot-branding/activation
```

No añade dependencias. Las pruebas sustituyen únicamente los comandos dentro del código de pruebas y nunca ejecutan herramientas reales de arranque. El binario real tiene raíz `/` y ejecutables fijos; no admite rutas alternativas ni modo de pruebas.

Antes de ejecutar: verificar paquete, cierre de dependencias offline, respaldo independiente del arranque **anterior** a instalar Plymouth, snapshot recuperable y recuperación local autorizada ensayada. Arrancar un kernel alternativo o probar un medio independiente; rescue con el mismo initramfs que se reemplazará no es suficiente. Solo admite el diseño BIOS/Debian13/ext4 documentado.

Secuencia aprobada desde consola root autorizada: `andeiva-boot-activation preflight`, `andeiva-boot-activation prepare --recovery-verified`, `andeiva-boot-activation apply`. La opción registra una declaración del operador, no una prueba automática de recuperación. Consultar `andeiva-boot-activation status`: `pending-reboot` no acredita un arranque correcto. Reinicio y comprobaciones de red/servicios son pasos independientes; la herramienta nunca reinicia.

`andeiva-boot-activation restore` restaura respaldos íntegros sin cambios ambiguos. Usa los destinos del kernel preparado incluso desde el kernel alternativo. Rechaza cambios desconocidos, respaldo corrupto o interrupción con bytes no observados; conservar evidencia y recurrir a recuperación independiente. No borrar respaldos ni recursos de un tema seleccionado. Solo admite una activación; no elimina respaldos automáticamente.

Tras una restauración completa, `prepare --recovery-verified` permite rearmar ese mismo conjunto si ambos kernels y todos los hashes originales/de contexto/efectivos coinciden. No reemplaza los respaldos. Otro contexto o cualquier cambio requiere recuperación revisada, no borrar el journal.

El menú queda visible cinco segundos. No modifica `10_linux`; pueden persistir mensajes ordinarios de carga. No garantiza A/B, resistencia a cortes, reversión de paquetes completa ni branding terminado. Consultar [diseño](../DESIGN.md) y sus pruebas nativas pendientes.

El arranque normal utiliza `loglevel=3`: conserva emergencias, alertas y mensajes críticos del kernel en consola; los errores y avisos ordinarios permanecen en el registro para diagnóstico autorizado. Esc muestra los diagnósticos textuales disponibles; para ver todo el kernel usar un arranque temporal sin `quiet`/`loglevel=3` o con nivel de consola superior. No cambia los argumentos de recuperación, bloquea drivers, omite comprobaciones del sistema de archivos ni desactiva registros. Puede aparecer texto de comprobación del disco antes de Plymouth; requiere observación nativa.

El arranque normal usa `systemd.show_status=error`: oculta las líneas de servicios correctos y conserva los estados de fallo y el journal. Comprobar la consola real tras salir de Plymouth.

## Comprobaciones portables y diagnóstico temporal

La elegibilidad usa la topología real de montajes y el tamaño de bloque del sistema de archivos, no el nombre del disco ni el hipervisor. Las pruebas del parser no acreditan validación nativa de Proxmox, servidores físicos o firmware no ensayado.

Solo el operador de plataforma autorizado puede usar `andeiva-boot-activation apply --diagnostic-boot`, después de restaurar y preparar con una nueva declaración de recuperación. Envía la traza a `/dev/null` y conserva un búfer acotado, potencialmente sensible, en `/run/andeiva-boot-plymouth-debug.log` al terminar Plymouth. No introducir credenciales en preguntas de Plymouth durante este ensayo de laboratorio. Se rechazan parámetros debug previos y un archivo de traza preexistente. La comprobación de capacidad no reserva espacio tras reiniciar.

Después de terminar Plymouth, verificar que la ruta fija sea un archivo regular, de root, modo 0600 y menor de 1 MiB antes de recogerla privadamente. Nunca subir trazas sin filtrar a Git, CI, administración ordinaria o paquetes de soporte. La traza puede ser incompleta; otro reinicio puede sustituirla. No modifica controladores, conectores, resolución, firmware ni argumentos de recuperación.

El diagnóstico permanece seleccionado hasta ejecutar `restore`, `prepare --recovery-verified`, `apply` normal y reiniciar normalmente. Se rechaza cambiar de modo con una configuración pendiente; repetir el mismo apply es idempotente. Recoger primero la traza y retirar el diagnóstico antes de devolver el appliance al uso habitual.

## Compatibilidad gráfica opcional

Ante un fallo de presentación DRM observado, y tras comprobar la recuperación, ejecute `restore`, `prepare --recovery-verified` y `apply --redraw-compatibility`. Este modo explícito añade el argumento estándar de refresco de Plymouth solo al arranque normal. No fuerza una resolución ni cambia controladores; el modo predeterminado no cambia. No puede combinarse con el arranque de diagnóstico.

Compruebe un reinicio real, el logo y los textos completos, los diagnósticos con Esc, la salud del servicio y el consumo de CPU/RAM. Los restablecimientos más frecuentes de la imagen pueden aumentar el trabajo gráfico; una vista previa no basta para validar la plataforma. Para retirar la opción, restaure, prepare de nuevo, ejecute `apply` sin opciones y reinicie. No se afirma compatibilidad universal.
## Instalación offline pendiente

Si aparece `ANDEIVA_BOOT_OFFLINE_INSTALL_PENDING`, no reintente la activación ni la restauración y no borre el marcador solo porque desapareció un PID o un bloqueo. Una instalación interrumpida puede dejar procesos de paquetes activos. Las consultas `status` y `capabilities` para root siguen disponibles. La recuperación local autorizada debe revisar el diario y los respaldos del instalador y comprobar que terminó el procesamiento de paquetes antes de resolver el estado pendiente. No se ofrece rollback automático de paquetes ni garantía ante cortes eléctricos.