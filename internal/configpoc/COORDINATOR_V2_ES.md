# Coordinador interno de configuración v2

Preparación inactiva sobre el mismo almacén v2. No está conectado al appliance,
Web/CLI/API ni helpers; no migra instalaciones ni anuncia v2 automáticamente.
Conserva los esquemas 4/3 y sus hashes dentro de referencias compuestas de esquema
5. Los contadores por dominio son independientes del global. Candidate, Running,
Startup y LastGood permanecen separados; Save es explícito.

Exige sujeto confiable autenticado y rol admin. Admisión sin efectos; pending e
intent persistidos antes de Apply. Comprueba todos los componentes antes de
seleccionar estado, resultado y auditoría juntos. La incertidumbre bloquea nuevas
mutaciones. Commit Confirmed mantiene plazo y recuperación independientes de la
sesión/namespace, con reserva propia. Rollback requiere evidencia de una revisión
verificada. Las mutaciones de servicios locales se rechazan hasta completar sus
pruebas de listeners y confirmación.

Los comandos reproducibles están en la [guía inglesa](COORDINATOR_V2.md).
La prueba opcional realiza 5.000 ciclos, 30.000 operaciones y 20.000 Apply
simulados; informa RSS/heap/CPU y uso lógico/asignado de disco/inodos. Requiere
varios GiB y cientos de miles de inodos en un directorio de pruebas aislado.
No demuestra tráfico nftables, cortes eléctricos ni continuidad del appliance.
Siguen pendientes integración de motores, identidad durable, paridad Web/CLI/API,
activación voluntaria, servicios locales y calificación física del almacenamiento.
No se elimina auditoría protegida ni se promete retención infinita.
