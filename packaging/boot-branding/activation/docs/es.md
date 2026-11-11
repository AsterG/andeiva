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
