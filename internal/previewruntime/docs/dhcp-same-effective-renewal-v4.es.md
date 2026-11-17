# Renovación DHCP idéntica: perfil interno

Requisito previo de desarrollo, apagado por defecto. Sólo el ensamblado confiable
selecciona `RoutedDHCPSameEffectiveRenewalV4` antes de tener lease/gate/Work. Este
cambio no activa fábricas, ajustes administrativos ni el runtime instalado.

Un epoch/secuencia nuevo y autenticado sólo refresca el mismo propietario,
interfaz y delta L3 efectivo canónico completo. Work conserva su procedencia y
undo inmutables. Se cierran reenvío y token anterior y se comprueban antes de
refrescar evidencia. Abrir exige autoridad actual, política, integridad completa
y secuencia nueva. Un fence irreversible nunca se resetea.

Hay un corte breve por renovación. Siguen pendientes las pruebas nativas con
TCP/UDP persistentes, cada corte y mínimo/mediana/máximo, observaciones de pérdida
y recursos. El propietario decide el máximo aceptable tras ver las mediciones;
este componente no afirma acceso sin pérdidas.

Tras inspección incompleta, el controlador solicita `refresh_only` con el Work
retenido antes de leer al propietario. El helper valida el vínculo y cierra
antes de comprobar readiness, owner o hash que puedan fallar. Este camino puede
refrescar evidencia manteniendo el cierre: nunca abre, crea Work, retira la
configuración seleccionada ni inicia otra adquisición.

Retirar una instancia V4 renovada verifica baseline original y retiro
seleccionado, libera L3 y conserva el mismo gate cerrado con su watermark.
Ese runtime es terminal: rechaza Begin y cambios de perfil. La limpieza normal
del helper libera el gate cerrado; cierre incierto/fence conserva el error.
La identidad nueva pertenece a PR posteriores de contrato y comportamiento.

Cancelar antes del primer frame no consume secuencia ni inutiliza el canal del
owner. Fallos después de iniciar el intercambio mantienen su cierre estricto.
Pruebas con sesión/codec/controlador/scheduler y Gate reales, dobles controlados
de kernel/store. Sin nuevo daemon, worker periódico, dependencia ni formato
persistente; calificación nativa y recursos de la integración pendientes.
