# Observación de flujos enrutados de sólo lectura

Tarea `ROUTING-ALPHA-001/routed-flow-observation`. Módulo interno de laboratorio;
revisión independiente, transporte nativo, tráfico y recursos pendientes. No se
conecta a Web/CLI/API, persistencia, paquetes o activación de motores.

`Collect(context.Context)` solicita exclusivamente un dump IPv4 `CT_GET|DUMP` de
conntrack vía NETLINK_NETFILTER en el namespace **actual**. No acepta nombres de
namespaces, setns, comandos, shell ni modificaciones de rutas/NAT/sysctl. No usa
NEW, DELETE o GET_CTRZERO; no reinicia contadores, captura paquetes ni procesa
paquetes en userspace. El launcher confiable controla namespace, privilegios,
dependencias, límites de salida y duración del proceso.

Se exige `/sys/module/nf_conntrack_netlink` preexistente. El colector no carga el
componente ni cambia de motor. Actualmente falta en el laboratorio Debian; el
orquestador prepara la dependencia de forma autorizada antes de calificarlo.
Kernels built-in sin ese directorio se rechazan conservadoramente.

Valida emisor kernel, grupos, puerto local, secuencia, multipart, tipos/longitudes,
flags y duplicados de atributos, tuples duplicados y fin de dump. Truncamiento,
overrun, interrupción, ENOENT y error nunca equivalen a un dump vacío válido.
Atributos desconocidos se acotan y validan estructuralmente, sin exportar sus
datos. El padding explícito puede repetirse sólo en grupos UAPI de contadores y
timestamp. Headers/TLV usan endian nativo; valores conntrack usan orden de red.

Límites: 64 KiB/datagrama, 4 MiB/dump, 8192 mensajes, 4096 flujos, 256 atributos
por registro, seis niveles y dos segundos. Cancelación se revisa al menos cada
50 ms durante polling. Cualquier error devuelve cero snapshots, aunque existan
registros leídos. Un dump completo no es una vista atómica durante tráfico vivo.
El launcher debe consumir/acotar stdout y aplicar su propio plazo de proceso.

Se informan únicamente TCP/UDP IPv4; otros protocolos se cuentan como omitidos.
`original` y `reply` conservan los tuples del kernel. `forward_translated` invierte
reply; `reply_translated` invierte original. `source_changed` y
`destination_changed` comparan endpoints, sin afirmar ausencia de NAT identidad.
Las vistas traducidas no inventan zonas. Zona conntrack no significa zona de
seguridad ANDEIVA.

Estado TCP, status, mark, ID, zona y timeout son opcionales y provienen del kernel.
UDP no recibe estado TCP/establecido inventado. Valores TCP nuevos conservan su
número y nombre `unknown`. Contadores de paquetes/bytes ausentes se omiten, no se
convierten en cero; `width_bits` distingue 32/64 bits. Paquetes/bytes se serializan
como cadenas decimales, manteniendo `uint64` interno y precisión más allá de
2^53; se rechazan números JSON para esos contadores. No se deducen tasas,
latencia, aplicación, usuario, permiso vigente o resultado de inspección. Mark o
conexión presente no demuestra autorización actual. Las horas de inicio/fin son
lecturas del reloj local, no timestamps de eventos confiables.

Toda salida contiene evidencia sensible de plataforma. Un adaptador futuro debe
autorizar Platform Super Administrator en backend para API/CLI/export/jobs, con
auditoría, privacidad y retención. No hay superficie para admin ordinario ni
bypass de identificación/inspección. No se habilita accounting si falta. JSON se
emite una vez tras completar el dump; no se almacena ni registra. Errores usan
códigos estables sin diagnósticos kernel o endpoints.

Pruebas Linux/WSL con Go 1.27.4 y caché offline existente:

```bash
go test -race ./internal/routedflow ./cmd/andeiva-flow-lab
go test ./internal/routedflow -run '^$' -fuzz FuzzMultipart -fuzztime=10s -parallel=2
go test ./internal/routedflow -run '^$' -fuzz FuzzFlowAttributes -fuzztime=10s -parallel=2
go vet ./internal/routedflow ./cmd/andeiva-flow-lab
go test ./internal/routedflow -run '^$' -bench . -benchmem
go build -trimpath -o /tmp/andeiva-flow-lab ./cmd/andeiva-flow-lab
```

Los tests usan datagramas sintéticos/transporte falso y no ejecutan operaciones
privilegiadas; los tests de cancelación Linux paran antes de abrir/usar socket.
Cubren SNAT, DNAT/twice NAT, ruta sin traducción, campos opcionales, endian,
atributos corruptos, límites, peer/secuencia/multipart, truncamiento, errores,
duplicados, cancelación y concurrencia. Otras plataformas devuelven unsupported.

Después de revisión, el orquestador ejecuta `/trusted/path/andeiva-flow-lab` sin
argumentos dentro del gateway aislado autorizado, con dependencia preparada.
Debe contrastar direcciones/puertos con flujos TCP/UDP conocidos y peers observados
por servidor; verificar accounting activo/inactivo, dump vacío, fallos y límites,
y preservar invariantes externos de rutas IPv4/IPv6 y nftables del host.

El runner integrado ofrece opt-in `--run-isolated-lab-with-flows`. Tras revisión
y preparación autorizada, ejecuta su propio child fijo `--observe-current-flows`
dentro del gateway creado, después de los probes SNAT TCP/UDP y antes de cambios
de reglas/cleanup. Revalida bindings y lectura semántica vigente; limita JSON a
1 MiB y rechaza campos duplicados/desconocidos. Exige ambos flujos TCP 18080 y
UDP 18081, origen LAN 198.18.0.2, destino WAN 198.19.0.2, reply e inversos coherentes,
origen traducido 198.19.0.1 y `source_changed` verdadero. PAT puede cambiar el puerto
origen; no se inventan métricas ausentes. Imprime datos reales únicamente como
`FLOW_OBSERVATION` en stdout privado de la unidad. El modo existente
`--run-isolated-lab` no llama al observer y funciona con componente ausente.
No introduce carga de módulos, sysctl o rutas de helpers adicionales; prueba nativa integrada
cualificada por separado a continuación.

Rollback: parar/eliminar sólo el binario staged; cerrar el socket libera sus
recursos. No crea objetos de red ni estado persistente. Sin cambios Docker/EKS,
runtime o dependencias. CPU/RSS y rendimiento nativos siguen pendientes; no hay
afirmaciones de producto. [Diseño y referencias](../README.md).

Evidencia de fuente: unit/stub Windows, race/vet offline Linux/WSL, ambos fuzz de
diez segundos y cross-build Linux amd64/arm64 y Windows/Darwin unsupported PASS.
Gosec sin hallazgos/supresiones y Gitleaks sin secretos. Microbenchmark sintético
WSL: 6526 ns/op, 10416 B/op, 62 allocs; no mide CPU/RSS del dump real o capacidad
del appliance. Ninguna prueba de fuente abrió sockets conntrack reales.

La ejecución nativa en Debian 13 AMD64 pasó en tres namespaces aislados:
conntrack TCP/UDP real con tuplas original/reply/traducidas coherentes con SNAT.
Contadores no disponibles permanecieron ausentes. Pasaron también ICMP related,
denegación IPv6/reversa, revocación de conexión establecida, routing sin NAT y
NAT sin autorización de forwarding. Las rutas IPv4/IPv6, nftables y forwarding
del host permanecieron idénticos; namespaces eliminados. El módulo local se
preparó expresamente fuera del collector y se retiró su módulo hoja al terminar.
Runner combinado: 3,853 s, CPU 0,395 s, pico cgroup 30.924.800 bytes, incluida
caché; no mide RSS exclusivo del collector ni capacidad de producción. No activa
API administrativa ni rutas del appliance.
