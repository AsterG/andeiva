# Lanzamiento del runtime agrupado V3

Esta biblioteca Linux conecta las factories V3 existentes en procesos separados. Es un componente experimental de integración; no es un comando de despliegue ni acredita preparación para producción.

El supervisor root confiable llama a `StartRoutedLaunchV3` con descriptores fijados de namespaces aislados, directorio de sockets propiedad del helper, almacén seleccionado propiedad de la API y tres pools de reserva provisionados. Conserva esos recursos hasta que termina `Close`. El binario despacha únicamente `RoutedHelperRoleV3` y `RoutedAPIRoleV3` hacia `RunRoutedLaunchRoleV3` y sale cuando esa función retorna.

La API permanece en el namespace del host sin capacidades. El helper entra al gateway aislado sólo con `CAP_NET_ADMIN`. Su grupo suplementario lector es distinto de los grupos IPC y API. El ejecutor usa `NewInOwnedNamespaceWithReader` con ese grupo confiable y ambos descriptores de namespace; el constructor anterior conserva sus restricciones originales.

Los descriptores heredados son fijos: 3 namespace gateway, 4 directorio de sockets, 5 almacén seleccionado, 6 pool admission, 7 pool plan, 8 pool emergency, 9 pipe bootstrap, 10 pipe control, 11 pipe eventos, 12 namespace host. Namespaces y directorios se abren sólo para lectura; los pipes pertenecen a root. Se validan las posiciones antes de reabrir roots y se rechazan alias, tipos y modos incorrectos. El bootstrap acotado vincula padre root, arranque, namespaces, identidades y perfiles.

La factory helper proporciona la autoridad existente y una sesión `NewRoutedCompatibilitySessionV2`. La factory API devuelve `OperationsRuntimeOptionsV2` con el almacén heredado y su perfil lector. No debe abrir un escritor antes de `OpenRoutedOperationsRuntimeV3`. Cada factory devuelve sus recursos adicionales mediante `Cleanup`.

El helper crea sockets Unix después de reducir privilegios. Ambas partes verifican UID, GID y PID reales del peer; no se hereda un socketpair creado por root. `ServeAPI` recibe el runtime abierto y el callback `ready`. Enlaza su listener TLS confiable después de boot/resume y readback, llama a `ready` exactamente una vez y termina al cancelarse el contexto. Helper listo no significa API lista.

`RestartAPI` termina y recoge la API anterior, drena sus canales sin cancelar un efecto en curso y después libera el bootstrap de la nueva API. El handshake V3 avanza la barrera del controlador antes de abrir el nuevo escritor. Helper y guardian permanecen vivos. Un reinicio fallido bloquea nuevos reinicios de ese supervisor; se recupera cerrándolo y siguiendo el procedimiento aprobado del fixture.

`Close` termina y recoge los dos hijos directos. La pérdida del helper también termina la API. Las señales por muerte del padre mantienen vivo el hilo creador hasta recoger cada hijo. El llamador conserva la responsabilidad de limpiar el fixture y demostrar la terminación de descendientes antes de retirar sus namespaces. La biblioteca no crea cgroups, provisiona interfaces, activa servicios del host ni acredita limpieza completa de descendientes.

Comandos desde la raíz del repositorio:

```sh
go test -race -p 1 ./internal/previewruntime ./internal/networkexecutor -count=1
go vet ./internal/previewruntime ./internal/networkexecutor
go build ./...
```

Las pruebas focales cubren argumentos de privilegios fijos, eventos acotados, rechazo de PID incorrecto, drenaje/barrera y grupos lectores. Las pruebas Unix dentro del mismo proceso no demuestran el bootstrap privilegiado entre procesos. Permanecen como gates separados las factories nativas de tres procesos, negativas de descriptores, recuperación por pérdida de procesos, limpieza de descendientes y mediciones CPU/RAM. Este incremento no incluye despliegue Docker/EKS.
