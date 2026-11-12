# Transacciones v2 preparadas de servicios locales

[English](TRANSACTIONS_V2.md) · [Português](TRANSACTIONS_V2_PT.md)

Esta integración une el resolver/libro de evidencias con el único coordinador v2.
No activa rutas HTTP/SSH, capacidades anunciadas, helpers desplegados, listeners,
reglas del host ni interfaces. Conserva esquemas firewall 4, local 3 y compuesto 5;
no crea otra base de configuración ni otro motor transaccional.

`OpenServiceV2WithLocalPolicy` exige una política del ensamblador confiable ligada
al mismo Manager de autenticación. El constructor ordinario sigue denegando
escrituras locales. `PreparedBridgeV2` fija la identidad del receptor desde el
listener; ningún cuerpo de petición aporta receptores o scopes. No añade contrato
público de transporte.

La sesión se verifica antes del lock de configuración. Bajo ese lock se comprueba
el registro canónico de sujeto/login/revisión de credencial, la operación admitida,
namespace, CAS global y proyección local. El resolver calcula objetivos y plazos;
Rollback exige además un testigo histórico compuesto verificado cuyo componente
firewall coincide con el actual.

Stage/Validate no necesitan tokens y rechazan evidencia irrelevante. Commit local
exige confirmación de 30–120 segundos; no admite aplicación inmediata. Rollback usa
30 segundos fijos sin cambiar el DTO. Commit/Rollback/Save requieren prueba de
recuperación. Confirm exige también una prueba por cada binding habilitado; con
todos deshabilitados sólo necesita recuperación. Save se rechaza durante pending.

La reserva del conjunto completo es atómica y precede al intent durable y los
efectos. Se libera sólo si no hubo admisión demostrablemente; una publicación
seleccionada o incierta consume la reserva. El replay final reautentica, pero no
necesita tokens antiguos ni repite efectos. La prueba de recuperación queda ligada
a la sesión exacta; los endpoints admiten otra sesión vigente del mismo sujeto y
revisión de credencial. TTL de 20/60 segundos, limitado por ventana y deadline.
Tokens y handles nunca forman parte de configuración/auditoría ni serialización.

Candidate/Running/Startup y sus generaciones permanecen separados por dominio;
las operaciones locales conservan la candidata del firewall. Sólo existe una
activación/confirmación global pendiente. Ambos dominios requieren readback antes
de seleccionar resultado. Guards y rollback usan el dominio y lease originales.
Timeout/reinicio se recuperan con intent durable y readback autorizado, sin sesión
ni tokens del usuario. El resultado histórico del origen no se modifica.

Stage/Validate/Save nunca reparan drift aplicando reglas. Si aparece entre lecturas,
queda cercado sin Apply ni Running no verificado. La ejecución local admitida usa
un contexto independiente y acotado; conserva deadlines anteriores. La publicación
de pruebas de listeners ocurre después del readback y selección pending, mediante
una vista específica sin inventar una operación Confirm. Su callback sólo consulta
el registro de instancias en memoria: no auth, coordinador, disco, red ni motores.
Sustituir una instancia invalida sus pruebas anteriores.

El primer intent local añade la característica requerida persistente
`local_services_transactions.v1`; puede coexistir con `boot_startup.v1`. El formato
por defecto anterior no cambia. La cualificación privada compiló el lector real de 9e59f35:
aceptó el store de control sin Apply y rechazó la característica local tras 216
selecciones antes de llamar a motores. No autoriza downgrade, cutover ni borrar
el historial.

Reproducción Linux/WSL, Go 1.27.4, dependencias offline:

```sh
GOPROXY=off GOSUMDB=off go test -race -buildvcs=false ./internal/configpoc ./internal/localadmin -run 'TestCoordinatorLocalV2|TestLocalTransactionsV2' -count=3 -timeout=5m
go test -race ./internal/configpoc ./internal/localadmin -count=1 -timeout=12m
go vet ./internal/configpoc ./internal/localadmin
go build ./cmd/... ./internal/...
```

Las pruebas de integración usan journal, autenticación, libro y guardian reales
con motores simulados. Las pruebas de fallos del coordinador simulan expresamente
la autoridad de evidencias y persisten hashes simulados entre salidas reales del
proceso. Ninguna demuestra reglas del kernel o listeners reales.

Quedan separados helper/listeners reales y handoff HTTP/SSH
y cutover Web/CLI/API. Un arranque del SO con Local Running distinto de Startup
sigue fallando antes de efectos: su activación segura es un siguiente trabajo
obligatorio. No se cierran reservas físicas/GC, exportación protegida, AND-01/02 ni
resiliencia global. Antes de activar, revertir retira código preparado sin uso;
un store seleccionado exige lectores compatibles, nunca escritores v1 en paralelo.

La cualificación nativa en Debian 13 ejecutó los binarios exactos como UID 1000,
con no-new-privileges y red aislada: tiempo combinado 3,916337 s, CPU 1,764321 s
y pico de memoria cgroup de 23.621.632 bytes. Incluye journals y pruebas de
autenticación/evidencia reales con motores simulados. No demuestra activación de
helper/listeners reales, rendimiento de tráfico ni recursos de todo el appliance.
