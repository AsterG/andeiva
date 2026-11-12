# Ensamblaje administrativo enrutado sin capacidades

`OpenRoutedOperationsRuntimeV3` es una fábrica Linux para el supervisor, no una
operación HTTP ni una opción de instalación. Consume dos sockets Unix heredados
distintos y los PID de helpers autenticados por el supervisor. El lanzamiento
verifica su procedencia; ninguna solicitud selecciona rutas o identidades.

La API debe cumplir UID/GID exactos, capacidades vacías y `NoNewPrivs` dentro del
namespace del host. Son obligatorios el perfil compartido fijado, tres pools ya
abiertos y plazos absolutos. El handshake v3 excluye al controlador anterior antes
del handshake v2 de compatibilidad, Snapshot/Attach o apertura del escritor.
Ambos canales son necesarios; no hay negociación, reenvío automático ni fallback.
La autoridad remota se vincula a metadatos confiables. Se rechaza una autoridad
proporcionada por el llamador. El coordinador conserva sus comprobaciones de
almacenamiento y pools.

Los sockets se transfieren al entrar y se cierran ante errores. Roots, pools y
motores locales siguen siendo del llamador. Cerrar administración libera escritor
y canales; no elimina reglas, namespaces, listeners ni el guardián independiente.

Las pruebas usan sockets Unix y credenciales reales con motores simulados:
orden de handshake, rechazo de identidad/perfil sin escribir almacenamiento y
conservación de la política al cerrar. No acreditan el ensamblaje completo con
almacenamiento compartido, tráfico, instalación ni reinicio del SO.

Linux: `go test -race ./internal/previewruntime -run TestRoutedAPIV3 -count=1`.
La fábrica no activa servicios desplegados.

Las comprobaciones previas de metadatos y perfil del directorio compartido sólo
leen identidad antes del handshake: no abren escritor, bloqueo ni realizan
escrituras. PID distintos requieren valores fijados por el lanzamiento confiable.
Esta fábrica no implementa ese lanzamiento ni aprovisionamiento del supervisor.
