# Diagnóstico privilegiado del ciclo de vida

El supervisor de namespaces, ejecutado como root, registra eventos acotados `failure` y `cleanup_failure` en su journal privilegiado existente. Sólo contienen categorías permitidas `phase`, `check` y `code`: nunca el error original, salida de comandos, namespaces, rutas, archivos o credenciales. Los errores de comandos ordinarios y de la API administrativa siguen siendo genéricos.

La categoría del primer fallo se captura en memoria acotada antes de limpiar recursos. Los diagnósticos se escriben sólo después de completar la limpieza: un escritor bloqueado no impide liberar recursos. El fallo de limpieza se conserva por separado y no sustituye al original. Se emite como máximo uno de cada tipo por proceso, sin reintentos ni historial en memoria. No cambian las comprobaciones del host, sentinel, listeners, plazos o requisitos de recuperación. El estado residual sigue necesitando la recuperación autorizada existente; estos eventos no permiten borrarlo ni reiniciar automáticamente.

La fase indica dónde se observó el fallo, no demuestra su causa. Un timeout al comprobar listeners no prueba que hayan caído. Un incidente histórico sin estos registros no puede diagnosticarse retrospectivamente sólo por su error genérico. El acceso al journal es privilegiado; no incorporar estos diagnósticos a la UI ordinaria, exportaciones ni paquetes de soporte generales.

Los controles positivos directos e inversos conservan su causa y contexto cuando ya fallan. Los comandos con fallo inesperado conservan el error del hijo y el contexto del comando. Así sobreviven las categorías existentes `canceled`/`deadline`, sin campos nuevos. Salida 0 sigue siendo éxito y 10 sigue indicando ausencia de respuesta; un no-echo sin causa sigue siendo genérico. No cambian reintentos, plazos, listeners, políticas, limpieza o reinicios. No determina la causa de una caída pasada.

Pruebas sin privilegios en Linux con Go 1.27.4:

```sh
go test -race ./internal/nftfixture ./internal/previewnet ./cmd/andeiva-preview -count=3 -timeout=4m
go vet ./internal/nftfixture ./internal/previewnet ./cmd/andeiva-preview
go build ./cmd/... ./internal/...
```

Se usan comprobaciones de salud simuladas y el formato real de errores del comando. No se crean namespaces ni se modifica el host. Se verifican orden, contexto original, causas conservadas, redacción y eventos independientes acotados. La prueba integral de fallo del servicio sigue pendiente.
Las regresiones adicionales usan peers TCP/UDP loopback reales que omiten o corrompen el eco y subprocesos reales cancelados, vencidos o fallidos. Verifican parada al primer fallo, semántica de salida intacta y los tres campos redactados existentes. La cualificación nativa de esta propagación sigue pendiente; la medición anterior indicada a continuación no cualifica este cambio.
La cualificación nativa en Debian 13 del binario exacto se ejecutó como UID 1000 con no-new-privileges y red aislada: tiempo de proceso 0,028980 s, CPU 0,016426 s y pico de memoria cgroup de 3.424.256 bytes. Son pruebas puras/con fixture simulado de diagnósticos: no demuestran un fallo real de namespaces, su causa ni el consumo del servicio completo.
