# Referencias de configuración enrutada

El resolvedor preparado del esquema 7 vincula firewall (esquema 4 o 6) y servicios
locales (esquema 3). Para el esquema 6, la referencia de red debe coincidir con la
red canónica incluida en ese mismo firewall. El esquema 4 exige red nula. La red
es una vista derivada, sin un segundo escritor.

Lee como máximo dos objetos mediante el lector acotado recibido. Comprueba
esquemas, bytes canónicos y hashes, conserva errores de almacenamiento y devuelve
referencias sin alias al documento original. El esquema 5 permanece intacto y
sigue rechazando el esquema 7.

Sólo valida el modelo: no migra almacenamiento, expone operaciones ni aplica
direcciones o reglas. La integración requiere Candidate/Running/Startup conjuntos,
una autoridad de activación, recuperación, auditoría y presupuestos verificados.
Confirmar varios helpers por separado no garantiza rollback conjunto.

Las operaciones enrutadas futuras deben incluir firewall y servicios locales en
el mismo conjunto, preservar trabajo ajeno y exigir confirmación para los cambios
iniciales de red. Save continúa siendo explícito. Validar el modelo no demuestra
conectividad, disponibilidad de listeners ni autorización.

```sh
go test -race -count=1 ./internal/configpoc -run 'TestRoutedComposite|TestRoutedEnvelope'
go vet ./internal/configpoc
```

Las pruebas usan lectores en memoria sin operaciones de red privilegiadas. La
aceptación del coordinador, runtime y transición nativa sigue pendiente.

[English](ROUTED_COMPOSITE.md) · [Português](ROUTED_COMPOSITE_PT.md)
