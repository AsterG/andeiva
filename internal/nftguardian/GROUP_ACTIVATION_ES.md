# Autoridad tipada del grupo de routing

`NewGroup(GroupEngine)` recibe `RoutedActivationBundleV1` y `RoutedTransitionV1`
aprobados. Comparte el núcleo privado de lease/timer/CAS de Guardian, sin introducir
el composite en `configpoc.Revision` ni crear leases por componente. Las APIs legacy
y los campos wire de State mantienen sus significados.

El ensamblaje confiable aporta un GroupEngine real. `ValidatePlan` es obligatorio:
verifica intent durable seleccionado, deadline original, lineage, cierre contextual
de objetos y reservas antes de timers/efectos. Formato/hash no es autorización.
No se incluye validador permisivo por defecto ni flag de activación.

`BootstrapStartup(ctx, transition, target, originalStarted)` exige `BeforeOwned`
físico verificado, sin hash de configuración efectiva. Calcula únicamente
`originalStarted + 10s`, arma rollback antes de aplicar y respeta ese deadline.
No afirma que PreviousRunning seleccionado estuviera aplicado. `State.Previous`
queda vacío en ese baseline físico frío; el digest del artefacto no sustituye un
hash de configuración. Root debe seleccionar plan real y recursos previamente.
Los fences R2/legacy permanecen; no convierte el bootstrap relativo en compatible.

`ArmUntil` vincula el before/target completo ya verificado y su ámbito de artefactos.
`ApplyLease`, `ConfirmLease`, `RecoverLease` y `MatchObserved` comparan transición
guardada y receipt exacto. Un Confirm exige readback completo del target físico y
de configuración. El receipt confirmado exacto resuelve respuesta perdida; recover
no revierte ciegamente un grupo confirmado. Rollback usa BeforeOwned exacto con
contexto acotado independiente; un readback fallido bloquea la autoridad.

Current/ObserveOwned deben leer componentes reales. El engine posee todos los
escritores network/firewall/local y aplica/restaura con orden deny-first. La fachada
no implementa ese engine, IPC, activación del coordinador, comandos kernel, pruebas
de endpoint ni almacenamiento. Su lease vive en memoria; la pérdida del helper
requiere la integración durable/recovery de Root. Sin segundo DB/catalogue/journal
ni éxito durable sin verificar.

```sh
go test -race ./internal/nftguardian ./internal/firewalladmin ./internal/firewallipc ./internal/previewruntime -count=3 -timeout=4m
go vet ./internal/nftguardian ./internal/firewalladmin ./internal/firewallipc ./internal/previewruntime
go build ./cmd/... ./internal/...
```

Pruebas de grupo con bundles tipados canónicos reales y resultados de engine
controlados; no cualifican activación física multi-componente. Pendientes runtime
nativo, endpoints, recursos y pérdida de procesos. Sin cambios host/manager/DHCP
ni promesas de inspección, continuidad absoluta, HA o release del appliance.
