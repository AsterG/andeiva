# Refresco de evidencia operacional del lease

Exige snapshots canónicos con secuencia nueva y la misma identidad, propietario,
interfaz, configuración y delta L3 completo. Sólo pueden cambiar secuencia, plazo
absoluto y hash. Admite un plazo nuevo más corto; nunca fabrica vigencia mínima.

El ensamblado de confianza autentica Work y prueba forwarding y gate cerrados.
El ejecutor verifica propiedad original, baseline, evidencia actual y estado
físico antes y después. Sólo actualiza evidencia en memoria; no escribe
direcciones, rutas, snapshot seleccionado ni R2.

Sólo el error de renovación clasificado permite cerrar y usar evidencia fresca.
Otros errores de autoridad mantienen el fence irreversible. El preflight del
gate cerrado rechaza secuencias consumidas sin efectos y nunca abre tráfico.

Reproducir: `go test -race ./internal/networkexecutor` y
`go vet ./internal/networkexecutor`. Incluye delta inmutable, replay, fallos de
readback, cancelación, lifetime terminado, fence y disposición. No añade procesos
ni trabajo periódico. No activa renovación ni califica tráfico o recursos del
appliance por sí mismo.
La opción interna `CloseOnExpiryV4` está desactivada por defecto. Su umbral de
BOOTTIME se toma antes de instalar el token y sólo puede adelantar el cierre.
Al vencer, Verify cierra la tabla exacta con un contexto acotado al ciclo de vida
y comprueba el cierre. Devuelve `ErrLeaseGateExpired`, conserva la secuencia
consumida y nunca reabre ese token. Una concesión autenticada nueva debe superar
todas las comprobaciones normales. Legacy, deriva anterior al umbral, fallo de
reloj y cierre incierto conservan el bloqueo. No amplía el plazo de la concesión.
Las pruebas incluyen vencimiento durante la lectura, replay, concesión nueva y
objetos ajenos. No añade procesos, temporizadores ni almacenamiento; la ruta
opcional añade lecturas de reloj. Integración y benchmark del appliance pendientes.
