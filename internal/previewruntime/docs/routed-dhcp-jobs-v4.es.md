# Integración del propietario DHCP seleccionado

El perfil explícito `RoutedLaunchResourcesV3.DHCPJobs` conecta runtime agrupado,
LAN bootstrap, productor root diferido y executor de lease existentes. Requiere
integridad. Static y NoNetwork no crean productor ni timer reconciliador DHCP.
El supervisor conserva un socketpair privado; API nunca lo hereda.

La primera preparación desde NoNetwork elige executor estático o LAN bootstrap,
manteniendo un solo escritor del namespace. Authority y DHCP comparten la misma
instancia LAN. Una red configurada mantiene su hash Desired exacto. Stage,
Prepare, Current y api_ready no inician adquisición.

Sólo después de inspect/check completo, helper verifica bundle seleccionado,
política idle real, lectura LAN y ausencia independiente de listeners. FD15
transporta prepare/activate/stop tipados. Root obtiene Desired del lector capless,
fija identidad/pidfd del productor y transfiere exactamente tres descriptores
reales. Activate confirma por canal privado el PID real de adquisición.

La barrera live es el mutex existente del store en ServiceV2.InspectRuntimeV1,
retenido durante todo el RPC y su revalidación final, más ownership del controller
helper. Root no espera otro checkpoint flock. Compara la referencia seleccionada
completa antes y después de Prepare/Activate; un cambio cierra el productor antes
del ACK. Helper vuelve a validar antes de publicar disponibilidad. Retirement usa
el flock retenido después de drenar procesos. Un resultado preflight no autoriza
efectos por sí solo.

dhcp_selected es sólo una pista privada para scheduling tras inspección completa.
R2 y el deadline BOOTTIME original autorizan cada cambio. El reconciliador consulta
cada 500ms sólo con DHCP seleccionado. La inspección pausa reconciliación sin
retirar un lease sano. Un fallo cierra token/forwarding y conserva evidencia R2
para retirar el lease correctamente. Secuencia RPC no modifica epoch del lease.

Rollback exige retirar WAN seleccionado y detener productor antes de restaurar
LAN. LeaseGate.Dispose conserva el gate cerrado para teardown del supervisor:
no se afirma ausencia total de reglas DHCP al reutilizar el scope ni reattach
arbitrario tras muerte del productor. Sin DHCP server ni cambios de red host.
Pendientes pruebas Debian de adquisición, renovación/pérdida, inspección,
reinicio API, rollback y drenaje; recursos y preparación productiva no demostrados.
