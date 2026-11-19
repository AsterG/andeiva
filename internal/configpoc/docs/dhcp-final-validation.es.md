# Validación final de lectura DHCP seleccionada

El candidato privado no es autoridad. La resolución DHCP comprueba Work e
identidad y después revalida todas las dependencias consumidas, reservas físicas,
selector y publicación pendiente antes de devolver una prueba. Los lectores
ordinarios conservan su validación. Ninguna caché sobrevive a la llamada; el
llamador mantiene la barrera de publicación/propietario durante los efectos.

La regresión compara `IOCalls` contabilizados con una validación final y con la
doble pasada anterior; luego ejecuta el resolver público con el presupuesto de
una pasada. Mide trabajo contabilizado, no syscalls, CPU ni latencia del disco.
Los lectores completo y de acción rechazan cambios de selector, Work, publicación
pendiente, reservas y cancelación. Action también rechaza una nueva dependencia
leída después del candidato; no se cubren adiciones arbitrarias no cacheadas de
Full. Las pruebas existentes cubren preparación, aplicación y retirada. Agotar el
presupuesto durante la limpieza debe anular la prueba pública. No se afirma
inyección de error de cierre de FD ni rendimiento nativo.

Ejecutar en Linux/WSL con Go 1.27.4:

```sh
go test -race ./internal/configpoc -run 'TestDHCPFinalValidationV3|TestRoutedDHCPSelectedV3.*Reader' -count=1 -timeout=180s
go vet ./internal/configpoc
```

Rollback por reversión del código, sin cambiar formatos ni configuración seleccionada.
