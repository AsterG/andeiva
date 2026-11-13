# Fixture nativo de lanzamiento agrupado V3

Estado: integración bloqueada antes de readiness de la API. Este fixture no es un despliegue de producción ni una calificación de tráfico.

`TestNativeRoutedLaunchV3` utiliza el launcher y ambas factories V3 reales. Un proceso separado con identidad API y sin capacidades prepara offline el almacén declarado y pools reales; cierra los escritores antes de convertir el perfil lector. El helper usa adaptadores físicos, observa ausencia real de listeners y exige ausencia de las tres tablas administradas antes del arranque. No obtiene readback de un simulador. El slot obligatorio del motor local rechaza cualquier acción y su contador debe permanecer en cero.

Las verificaciones positivas previstas incluyen UID/GID/grupos exactos, cinco conjuntos de capacidades, no-new-privileges, namespaces distintos, descriptores lectores, acceso denegado del helper a credenciales y lock escritor, autenticación real del peer V3, boot/readback agrupado, HTTPS con certificado verificado, rechazo anónimo, lectura autenticada y reinicio de API conservando PID del helper. Los dos enlaces dummy permanecen desactivados y sin direcciones ni rutas. No se acredita tráfico reenviado, muerte durante una operación pendiente, recuperación entre arranques del SO ni limpieza de descendientes durante un comando de kernel interrumpido.

Compilar en Linux con el toolchain del repositorio:

```sh
go test -c -o previewruntime.test ./internal/previewruntime
go vet ./internal/previewruntime
bash -n packaging/preview/tests/routed-launch-native.sh
```

Transferir mediante la conexión aprobada del laboratorio con identidad fijada y verificar hashes. Instalar en directorio nuevo propiedad de root, modo 0755; binario 0755 y script 0700. Ejecutar sólo en el cliente Debian 13 autorizado, dentro de unidad root con `PrivateMounts=yes`, `TemporaryFileSystem=/run/netns:mode=0755`, `ProtectSystem=strict`, `ReadWritePaths` limitado al directorio del fixture, `KillMode=control-group`, `LimitNOFILE=256`, `TimeoutStopSec=5s` y `RuntimeMaxSec=110s`. Comando de la unidad:

```sh
bash /APPROVED_FIXTURE/run.sh --isolated-lab /APPROVED_FIXTURE/fixture.test
```

El harness crea nombres únicos y comprueba inodos antes de limpiar. Rechaza eliminar namespaces con procesos presentes; la unidad contenedora mantiene la responsabilidad de limpiar descendientes. Conservar binario/logs fallidos y usar otra unidad/directorio para el intento siguiente.

Intento observado, 2026-11-12: binario SHA-256 `501a99e6d02b071b370108cad6947b7e29ba4ac7652516fe8bec1664eba4232f`, script SHA-256 `6c4e4707229c9c636c38ba55f4b2feb2f6e9f453d396f8fc72d787a78f95bbfc`. Helper: UID 62002, GID 62003, grupo suplementario 62004, sólo NET_ADMIN en los cinco conjuntos, NNP=1 y 57 descriptores de pools sólo lectura. La API no alcanzó readiness: `ANDEIVA_OPERATION_UNAVAILABLE`. Unidad exit-code 1; duración 427 ms, CPU 290395000 ns, memoria máxima 30687232 bytes. Son medidas de un arranque fallido, no del presupuesto operativo. Las comparaciones de reglas, rutas y forwarding del host pasaron y no quedaron namespaces nombrados, según el orquestador que ejecutó la unidad remota.

El binario diagnóstico agrega nombres de etapas fijos sin credenciales ni cuerpos de configuración. Compilación, vet y sintaxis shell pasaron. Éxito nativo completo y revisión de fuente final pendientes. Sin despliegue Docker/EKS agregado.
