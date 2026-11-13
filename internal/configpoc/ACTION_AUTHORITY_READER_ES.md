# Lector del cierre de autorización

[English](ACTION_AUTHORITY_READER.md) · [Português](ACTION_AUTHORITY_READER_PT.md)

El lector seleccionado conserva G1 completo como comportamiento predeterminado.
`SelectionReaderOptionsV2.Policy = SelectionActionAuthorityV2` es una selección
explícita del ensamblaje confiable; ninguna fábrica del appliance la habilita.
No es una opción del usuario, API, entorno o mensaje IPC.

El perfil valida la selección completa y las dependencias que autorizan la
operación actual: configuración canónica, Candidate, operaciones y testigos
referenciados, auditoría tipada, trabajo, baseline, recuperación, BootBoundary
y todas las reservas activas. Sólo consulta archivos históricos consumidos por
esas referencias; exige sus hechos finales tipados. Una auditoría opaca de
catálogo no acredita una operación del motor transaccional.

Conserva cada objeto consumido hasta la comprobación final, incluso si la caché
de descriptores está llena. Reabre los objetos sin descriptor retenido y compara
identidad, permisos, ACL y bytes. La memoria y las lecturas se cobran contra los
límites existentes; agotarlos o detectar cambios rechaza la autorización. No hay
caché de autoridad entre solicitudes ni aumento de plazos.

Este perfil no demuestra integridad de historia ajena a la operación. G1 completo
sigue siendo obligatorio para integridad, retención y GC. Antes de habilitar el
perfil en un runtime se necesitan G1 completo al arrancar, un bloqueo persistente
de nuevas modificaciones ante corrupción y programación segura de inspecciones.
El bloqueo debe preservar el dataplane conocido y el rollback ya autorizado.
Esos controles todavía no están integrados; no se acredita el presupuesto RPC
de tres segundos ni ejecución nativa de este perfil.

Las pruebas usan almacenes y archivos reales con motores simulados o limitados
a preparar cambios. Una comparación retira un objeto histórico ajeno al cierre:
el lector de autorización conserva su alcance y G1 detecta la corrupción. Esto
no autoriza borrar ese objeto ni afirmar integridad completa.

```sh
go test -race ./internal/configpoc -run TestActionReaderV2 -count=1
go test -race ./internal/configpoc -run TestSelectedReaderV2 -count=1
go test -race ./internal/configpoc -run TestSelectedCacheV2 -count=1
go vet ./internal/configpoc
go build ./...
```

Una prueba separada con almacén/IPC Unix reales selecciona este perfil tras G1
completo sin escritores. Con kernel/red simulados pasó con detector de carreras
y plazos RPC originales de tres segundos: 56,58 s total y máximo observado de
resolución 1,883935121 s. Comprueba Boot4, Candidate/Validate, Commit/Confirm/Save,
activación enrutada, reinicio del helper y rollback inverso. No habilita fábricas
del appliance ni acredita tiempos nativos o los controles de integridad pendientes.

```sh
go test -race ./internal/previewruntime \
  -run '^TestRoutedIPCV3ActionReaderSharedStoreLifecycle$' -count=1 -timeout=100s -v
```
