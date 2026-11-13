# Calificación del core de retirada de scope

Estado: fixture implementada; ejecución nativa y mediciones pendientes. Un skip
sin privilegios no acredita calificación nativa.

Sólo Root, en un laboratorio Debian 13 autorizado donde no existan
`andeiva-preview-grouped.service` ni su socket. Prohibido ejecutarla en CI, WSL
privilegiado o un appliance instalado. Dos invocaciones reales: la primera
persiste siete anchors antes de L2/Boot, inicia API sin capacidades/helper con
NET_ADMIN, verifica Boot y readback, espera los hijos y se mata con SIGKILL.
La segunda recibe los siete FD, prueba rechazo por lock ocupado y ejecuta el
core real de retirada con lector capless, G1/R2, drain, desmontaje, Drop y recibo.
ENODEV conserva evidencia y falla; no significa retirada completada.

RootDirectory y passwd/group privados; padres veth y MACVLAN sólo en namespaces
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

[English](en.md) · [Português](pt.md)
