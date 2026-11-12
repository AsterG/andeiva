# Reservas de recuperación transaccional

La ruta v2 es interna y aún no está habilitada en el runtime administrativo
instalado. No activa interfaces, forwarding ni NAT.

El almacén v2 seleccionado sigue siendo la única autoridad. El ensamblador abre
tres pools distintos: admisión de 4096 bytes, plan de 16384 y emergencia de 8192.
Cada pool tiene 18 posiciones: ocho ordinarias, ocho de cierre de confirmación y
dos del sistema. El solicitante no elige rutas ni posiciones.

Admisión vincula operación, identidad durable, dominio, generaciones y huella de
la solicitud. El intent seleccionado y el plan verificado preceden a la
aplicación. Emergency registra incertidumbre; no confirma ni publica Running.
Las reservas ausentes o inciertas bloquean nuevas escrituras. El helper conserva
el plazo independiente de reversión.

El archivo canónico conserva bytes exactos, finalidad y auditoría: 56 KiB máximos
de payload y 64 KiB del objeto completo. El índice identifica Lineage+Owner y cada
consulta verifica además Claim o Binding completo. El escrow no utilizado no
inventa una operación ni un binding. Reutilizar una posición exige el mismo
archivo en ambas raíces seleccionadas y CAS exacto de identidad, época y bancos.
La auditoría protegida permanece retenida; las reservas desconocidas se conservan.

Las reservas lógicas no son RAM, créditos comerciales, cuotas de disco ni prueba
de espacio físico. No aumentan el presupuesto configurado. El ciclo ordinario
completo debe caber en 16 MiB/64 inodos, incluyendo archivo, temporales y recuperación
de finalización parcial. Su admisión y cualificación ante fallos siguen en
implementación; no habilitar el runtime antes de verificarlas.

Reproducción con Go compatible con go.mod y dependencias autorizadas:

```sh
go test -race ./internal/recoveryreserve ./internal/configpoc -count=1 -timeout=15m
go vet ./internal/recoveryreserve ./internal/configpoc
go build ./...
```

TestReserveCoordinator usa journals/pools temporales reales y motores simulados.
TestReserveArchiveV2 comprueba límites, sustituciones y auditorías ausentes o
ajenas. Los cierres de proceso no prueban cortes eléctricos. Las pruebas nativas
de espacio finito y motores reales se documentan por separado; no existe una
garantía de producción, HA ni de resistencia a cualquier fallo físico.

El harness de volúmenes copiados admite `--authorized-debian-v2-reserve-volumes`
con los mismos siete argumentos que `--authorized-debian-v2-volumes` de la
[guía de almacenamiento](../storagevol/docs/es.md). Compilar el ejecutable con
`go test -c ./internal/configpoc`. Este modo explícito prepara los pools dentro
del volumen copiado y exige RUN/PASS y `ANDEIVA_NATIVE_R2_CASE_PASS` por caso.
Comprueba admisión ordinaria, lectura/reintento y recuperación de capacidad tras
agotar bytes/inodos o mantener abierto un archivo eliminado. El filesystem de
128 MiB debe rechazar Commit Confirmed sin capacidad física para su cierre.
No demuestra cierre de leases bajo agotamiento, reinicio completo del coordinador
ni motores reales de tráfico.

