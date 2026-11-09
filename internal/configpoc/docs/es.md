# Experimento de configuración transaccional

[English](en.md) · [Português](pt.md) · [Diseño y criterios de aceptación](../README.md)

Esta guía corresponde a un entorno local de desarrollo confiable. El experimento
modifica archivos temporales de configuración y estados de componentes simulados.
No configura un firewall, proxy, interfaz de red ni servicio ANDEIVA de producción.
No requiere privilegios root, Docker ni acceso de red a un appliance.

## Ejecutar las comprobaciones

Utiliza Linux con Go 1.27.3 ya instalado y un compilador compatible con el detector
de carreras de Go. WSL sirve para desarrollo; utiliza su sistema de archivos Linux
para las pruebas de persistencia, no un directorio montado desde Windows. Si falta
un requisito, registra el bloqueo; no debilites las pruebas ni instales herramientas
de compilación en el appliance para resolverlo.

Desde la raíz del código fuente:

```bash
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOTELEMETRY=off
go test -race -count=1 -v ./internal/configpoc
go build ./internal/configpoc
```

Registra el commit, la versión de Go, el entorno, la salida completa y el código
de retorno. Una compilación correcta solo prueba que el código compila. Las pruebas
omitidas y los escenarios de fallo no ejecutados no cuentan como aprobados. Los
almacenes temporales pertenecen al harness; nunca uses un directorio de datos del
appliance en su lugar.

Ejecuta el escenario independiente en un directorio privado nuevo del sistema de
archivos Linux:

```bash
umask 077
poc_parent=$(mktemp -d /tmp/andeiva-config-poc.XXXXXX)
go run ./cmd/andeiva-config-poc -state-dir "$poc_parent/state" -iterations 20 > "$poc_parent/report.json"
cat "$poc_parent/report.json"
```

El comando acepta entre 1 y 100 iteraciones y emite un informe JSON con aserciones
del escenario y observaciones de recursos. Requiere una ruta absoluta nueva para
el estado y un usuario Linux sin privilegios. Conserva el directorio y el informe
para inspección. No borra almacenes existentes, instala servicios ni aplica reglas
de motores reales.

## Transiciones y autorización

`stage` crea Candidate. `validate` lo comprueba sin cambiar Running. `commit`
coordina la aplicación en componentes y solo actualiza Running tras el éxito.
Con una ventana de confirmación, la revisión es provisional hasta `confirm`;
el vencimiento activa la compensación. `save` copia explícitamente Running a
Startup y no puede eludir una confirmación pendiente. `recover` intenta reconciliar
un estado efectivo no confiable. `revoke` es un estado protegido independiente
del guardado ordinario de configuración.

Son operaciones tipadas del servicio ejercitadas por las pruebas, no comandos
implementados en la CLI `andeiva` instalada. Las etiquetas Web, CLI y API utilizan
los mismos permisos del servicio. El harness proporciona identidades confiables;
no prueba sesiones de navegador, autenticación HTTP, MFA ni identidad SSH reales.

Reabrir un proceso y arrancar el sistema son casos diferentes. La recuperación del
proceso utiliza el estado transaccional persistido; el arranque explícito selecciona
Startup. Una transacción sin confirmar revierte de forma conservadora tras el
reinicio. La auditoría y las revocaciones deben persistir sin requerir `save`.
El temporizador funciona dentro del controlador. No hay un watchdog independiente
ni una concesión temporal impuesta por el motor que pruebe el cumplimiento del
plazo mientras el controlador esté caído.

## Fallos y recuperación

Conserva la salida y el comando exacto de una prueba fallida. No elimines bloqueos,
edites el historial, sustituyas hashes ni borres estados para obtener un resultado
aprobado. Si una operación de almacenamiento tiene resultado incierto, detén los
cambios y reabre mediante la recuperación prevista. Si un componente no puede
revertir, informa que requiere recuperación; un estado parcial no es un commit
correcto. Un directorio nuevo sirve para otra prueba aislada, no para sustituir
la recuperación del caso original que falló.

El almacén tiene capacidad finita. Rechazar nuevas operaciones al alcanzar el
límite conserva el historial; no constituye una política de retención o respaldo.
La configuración y los diagnósticos pueden contener información sensible. Mantén
las evidencias privadas y comparte solo lo necesario para reproducir el defecto,
sin credenciales ni datos ajenos al caso.

## Interpretación de resultados

La escritura de archivos, el ciclo de procesos, los bloqueos y la autorización
común pueden ser reales; la aplicación en componentes sigue simulada. Registra
estas categorías por separado. Mide CPU, memoria residente, crecimiento de disco
y latencia para la carga ejecutada. Un benchmark de configuración pequeña no
demuestra throughput de paquetes ni certifica la capacidad del appliance.

Interrumpir procesos, sincronizar archivos y reiniciar no demuestra resistencia a
un corte físico de energía. Este experimento no selecciona SQLite o PostgreSQL,
implementa HA, firma historiales, cifra secretos, proporciona autenticación de
producción ni valida coordinación real de nftables/proxy. Esos gates siguen abiertos.
