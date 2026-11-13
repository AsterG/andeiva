# Recuperación enrutada tras reiniciar el sistema operativo

Un BootID nuevo y confiable es distinto de reiniciar el controlador o helper. El
coordinador no envía planes del namespace anterior a la nueva instancia ni amplía
el plazo de confirmación antiguo. El arranque carga Startup y conserva Candidate,
su propietario y su base original.

Ante una confirmación o intento de arranque pendiente, un descriptor privado tipado
retiene configuración, trabajo, operación/registro y reserva originales. El nuevo
arranque observa su namespace realmente vacío, selecciona un Intent nuevo y usa
el plazo original de diez segundos de ese nuevo registro. Pending antiguo permanece
internamente hasta verificar Startup; Running histórico no se presenta como
confirmado. La API no queda disponible durante la transición.

Sólo la finalidad verificada del nuevo arranque permite resolver la contabilidad.
El resultado original de la operación es inmutable. La auditoría indica
`superseded_by_boot`, no una restauración del objetivo anterior. Se exigen ambos
anclajes seleccionados del archivo y el retiro físico antes de liberar la reserva.
Un marcador persistente impide interpretaciones silenciosas de lectores antiguos.

Las pruebas usan almacenamiento y reservas reales con autoridad de grupo simulada.
No demuestran tráfico, cortes de energía ni arranque físico. Se rechazan el mismo
BootID, roles/run ajenos, pruebas sustituidas y plazos vencidos. Un segundo reinicio
del sistema con un descriptor aún pendiente queda bloqueado antes de reservar otro
slot: no se amplían ni reutilizan silenciosamente los dos slots de sistema. Sigue
vigente el espacio canónico requerido para arrancar. La calificación con
almacenamiento totalmente agotado y las métricas nativas son controles separados.

Reproducción Linux: `go test -race ./internal/configpoc -run
'TestRoutedOSBootBoundary|TestReserveEnvelopeMaximumDescriptors' -count=1`.
