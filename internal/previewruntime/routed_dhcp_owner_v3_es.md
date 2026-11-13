# Propietario de adquisición DHCP enrutada v3

Estado: implementación aislada. Pendientes integración del runtime agrupado,
revisión independiente, pruebas nativas DHCP/privsep y mediciones de recursos.
Contrato interno de desarrollo, no manual operativo del appliance.

Reutiliza `dhcpclient.StartIsolated` y el perfil fijo de dhcpcd mantenido.
No configura direcciones, rutas, DNS, listeners, Forward ni NAT. El lease es
evidencia para el runtime seleccionado; no autoriza políticas nuevas.

Sólo el supervisor root puede invocar `StartRoutedDHCPOwnerV3`, que inicia la
adquisición inmediatamente. Antes debe verificar integridad del helper, revisión
DHCP canónica seleccionada, bootstrap/readback LAN y EmptyListeners independiente.
No se permiten excepciones a estos gates. WAN estática no debe crear proceso;
los planes sin DHCP se rechazan. La integración de este orden sigue pendiente.

El rol separado necesita root por los requisitos existentes de namespaces,
montajes privados y privsep de dhcpcd. NET_RAW aislada no está validada. Revisar
capacidades y filtros del unit root antes de activarlo. API sigue sin privilegios;
helper mantiene NET_ADMIN. No se modifican unidades ni despliegue.

El supervisor aporta descriptors retenidos y estado canónico, nunca autoridad
procedente de API/CLI/helper. Ejecuta únicamente su binario confiable con el rol
`RoutedDHCPOwnerRoleV3`, mediante argumentos fijos de `/usr/bin/nsenter`.
El dispatcher deberá llamar `RunRoutedDHCPOwnerRoleV3`.

FDs del rol separado: 3 namespace gateway, 4 namespace de red host, 5 namespace
de montajes host, 6 bootstrap, 7 eventos, 8 petición Current, 9 respuesta Current,
10 Stop exclusivo root. No cambian FD13/FD14 del helper. El integrador debe
asignar nuevos FDs del helper y cerrar copias paternas después de heredarlos.
`TakeReaderFiles` permite una sola transferencia. Nunca entregar el binding o
los descriptors a API; el contenido del binding por sí solo no autentica.

Se comprueban padre root/PID/start, namespaces, cgroup, pipes privados y vínculo
nombre/MAC/índice de interfaz. Root fija con pidfds tanto el rol como el proceso
dhcpcd real y vuelve a comprobar identidad y vida antes de transferir autoridad.
Current serializa peticiones nuevas, con frames máximos de 8 KiB y dos segundos
incluida espera del lock. Secuencia RPC y secuencia/epoch del lease son distintas:
consultas repetidas devuelven el mismo fact y plazo BOOTTIME original.

JSON malformado/duplicado, replay, incarnation incorrecta, EOF, cancelación,
muerte o caducidad rechazan acceso; nunca hay fallback a lease almacenado.
Indisponibilidad revoca el epoch; solamente otro epoch confirmado lo reemplaza.
TIMEOUT almacenado no otorga autoridad. No se extiende plazo al consultar.
Current no admite comandos, rutas, Stop ni renovación forzada: dhcpcd mantiene
su renovación/rebind. Stop sólo entra por el canal root y espera hijo y
descendientes adoptados antes de confirmar. Control inválido o EOF detiene sin
confirmación de éxito. Ante muerte abrupta o fallo de inicio, es obligatorio
drenar todo el cgroup dedicado antes de retirar el scope, usando el gate existente.

Los montajes sólo cambian dentro del namespace privado verificado: propagación
privada, `/run` y `/var/lib` tmpfs de 4 MiB cada uno y tres directorios de 1 MiB,
128 inodes por montaje, nosuid/nodev/noexec. Es capacidad máxima, no RSS medido.
No hay sockets públicos ni timers recolectores. Se descarta salida de procesos;
los errores del protocolo usan códigos genéricos estables.

Pruebas reproducibles con Go 1.27.4, `GOTOOLCHAIN=local`:

```sh
go test -race ./internal/previewruntime -run TestRoutedDHCPOwnerV3 -count=1 -timeout=2m
go test -race ./internal/previewruntime ./internal/dhcpclient -count=1 -timeout=3m
go vet ./internal/previewruntime ./internal/dhcpclient
go build ./internal/previewruntime ./internal/dhcpclient
GOOS=windows GOARCH=amd64 go test -c ./internal/previewruntime -o /tmp/andeiva-owner-windows.test.exe
```

Las pruebas usan pipes, evidencia ficticia y un proceso sin privilegios para
pidfds. No ejecutan DHCP, montajes ni cambios de red. No prueban funcionamiento
nativo, Docker/EKS, ACK real, renovación, reinicio ni limpieza del cgroup.
Otras plataformas rechazan inicio/reader. Rollback: retirar estos archivos
nuevos aún no integrados; no cambia configuración instalada ni estado compartido.
