# Diagnóstico nativo de adquisición DHCP

Instrumentación experimental de laboratorio; no acredita WAN funcional. El plazo de adquisición sigue en 35 segundos. Sólo el owner del supervisor ejecuta el harness nativo aislado después de revisión independiente.

Compilar un artefacto separado, nunca empaquetarlo ni desplegarlo:

```sh
go test -c -tags andeiva_native_dhcp_diagnostics -o /tmp/andeiva-dhcp-jobs-diagnostics-v4.test ./internal/previewruntime
```

Registrar commit exacto y SHA-256. La compilación ordinaria descarta stderr y no crea archivo, registro, worker ni timer de diagnóstico. La fixture también informa tiempos acotados de sus llamadas existentes reconcile/current/live, sin RPC adicional de autoridad.

El artefacto clasifica stderr mediante códigos fijos y registra motivos validados del hook, etapas de fallo y tiempos BOOTTIME. No conserva opciones, direcciones, hostnames ni frames crudos; tampoco agrega un segundo lector al pipe del protocolo. Crea exclusivamente un archivo root0600 dentro de un directorio root0700 en el tmpfs privado existente: `/run/andeiva-dhcp/native-diagnostics/events.jsonl`. Límite 64 KiB, marcador explícito de truncamiento y descarte posterior.

La fixture registra un único consumidor antes del lanzamiento. Tras validar el bootstrap root, verifica handle real, pidfd/start ticks, identidades de red/mount y cgroup; retiene el directorio antes de Activate. Recoge datos mientras el producer vive y antes del cleanup, sin redescubrir PID después del teardown. Libera explícitamente registro y pins. Diagnóstico no disponible falla la fixture diagnóstica; nunca acredita adquisición silenciosamente.

Exigir unit tests con/sin tag, race, vet y compilación antes del native ejecutado por root. Este perfil no autoriza ampliar plazos, privilegios, políticas de paquetes ni relajar inspección. Su sobrecarga no constituye benchmark de producción.

Diagnóstico de duración: los hooks de concesión aceptados incluyen sólo el número validado `lease_seconds`; la expiración no inventa una duración. T1/T2 no pertenecen al evento validado y no se infieren. La traza distingue errores de canal, espera inicial, conflicto, almacenamiento y capacidad; registra los cambios de clase dentro del mismo límite de 24 registros. Los campos opcionales de época y trabajo son una lectura posterior a la llamada que no bloquea, no una prueba de la operación exacta que falló. No se añaden errores, opciones, direcciones ni nombres sin filtrar.
