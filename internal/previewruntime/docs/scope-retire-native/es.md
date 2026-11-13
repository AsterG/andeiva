# Calificación del core de retirada de scope

Estado: fixture implementada; calificación nativa y mediciones pendientes. Un skip
sin privilegios no acredita calificación nativa.
El primer intento nativo falló antes de Store o efectos de red: los API
filesystems ocultaron `/run/andeiva-preview/grouped`. El segundo bind hijo usaba
un origen dentro del árbol oculto y falló NAMESPACE/226 antes de ejecutar Go.
Ambos conservaron FDstore vacío; la retirada no pasó. Ahora se monta todo el
`/run` privado de la fixture con `norbind`, sustituyendo el fallback MountAPIVFS
en el mismo destino. La repetición nativa sigue pendiente.

Sólo Root, en un laboratorio Debian 13 autorizado donde no existan
`andeiva-preview-grouped.service` ni su socket. Prohibido ejecutarla en CI, WSL
privilegiado o un appliance instalado. Dos invocaciones reales: la primera
persiste siete anchors antes de L2/Boot, inicia API sin capacidades/helper con
NET_ADMIN, verifica Boot y readback, espera los hijos y se mata con SIGKILL.
La segunda recibe los siete FD, prueba rechazo por lock ocupado y ejecuta el
core real de retirada con lector capless, G1/R2, drain, desmontaje, Drop y recibo.
El tercer intento alcanzó Store/Boot real y se bloqueó en el antiguo rechazo
ENODEV, conservando siete FD. El core nuevo exige además revalidación de selección,
anchors, boot/namespace, unidad actual y drenaje; revisión y prueba nativa
pendientes. Los marcadores por InvocationID conservan fallos previos. Root puede
reintentar la unidad retenida con binario revisado e invocación nueva real; no
acredita el contador del driver de unidad nueva ni el handoff management.

RootDirectory y passwd/group privados; padres veth y MACVLAN sólo en namespaces
aislados. El bind writable de `/run` procede sólo de la raíz temporal, nunca del
`/run` del host, con ruta canónica y owner/modo comprobados. Los sockets del
manager siguen montados por separado sólo lectura; `/var/lib` también queda
dentro de esa raíz. No se crea RuntimeDirectory en el host. Los enlaces permanecen
aislados, sin direcciones, rutas ni reglas del host. Los padres modelan enlaces
externos y no forman parte del recibo del gateway. Su pin vive en el MNT privado
antiguo. La proyección operacional schema2 conserva exactamente Boot/Run/Host/GW
del bootstrap schema1; no altera la identidad seleccionada.

Alcance: core con raíces reales suministradas directamente. No califica loader,
procedencia de migración, restart managed, reboot ni handoff management de ocho
FD. El árbol de integración necesita el dispatch TestMain del preflight y las
consultas fijas systemctl con `SYSTEMD_OFFLINE=0` dentro de RootDirectory; no se
debilita LocalOrigin.
RootDirectory, PrivateMounts, MainPID e InvocationID se consultan al manager
real; no se leen symlinks de PID1 ni se añade SYS_PTRACE. El driver rechaza alias
de ruta por comparación canónica y exige PASS/exit exitoso de la invocación actual.

```sh
go test -race ./internal/previewruntime -run '^TestRoutedScopeRetireV3Native' -count=1 -v
go vet ./internal/previewruntime
go test -c ./internal/previewruntime -o /absolute/output/scope-retire.test
bash -n packaging/preview/tests/scope-retire-native.sh
# Sólo Root, tras revisión del artefacto e invariantes:
bash packaging/preview/tests/scope-retire-native.sh --isolated-lab /root-owned-0755-directory/scope-retire.test
```

Límites: dos invocaciones, timeout de prueba 90 segundos, 256 FD, 128 tareas,
384 MiB. SYS_ADMIN corresponde a la fixture, no al helper. El fallo conserva
unidad/FDstore/manifest/slot y archivos; no hay stop automático ni borrado
recursivo. El éxito exige segunda InvocationID correlacionada, FDstore vacío y
MainPID cero antes de detener esa unidad. Conservar journal, propiedades, hashes
y recibo. Root debe comparar direcciones/rutas/rules IPv4/IPv6, nftables,
forwarding, namespaces y mountinfo de PID1 y registrar CPU/RAM reales.

Mientras la recuperación necesite descriptores retenidos, no ejecutar
`reset-failed`, detener ni recrear la unidad transitoria fallida. Un
`reset-failed` observado provocó la recolección de la unidad por el manager y la
pérdida de los siete descriptores. El manifest restante no autoriza adopción ni
recibo de retiro. Conservar la evidencia original; un reintento directo tras
vencer el límite de arranques requiere verificar los descriptores retenidos y
una nueva invocación real. Las comprobaciones de éxito de este driver para una
unidad nueva no califican ese reintento.

Los errores de recuperación Root identifican etapas fijas y conservan la causa.
Un `EPERM` aislado no demuestra qué capacidad u operación falló; observar la
etapa de entrada al mount namespace antes de cambiar el presupuesto de capacidades.

[English](en.md) · [Português](pt.md)
