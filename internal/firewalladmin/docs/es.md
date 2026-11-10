# Laboratorio administrativo de firewall — Español

Estado: implementación experimental y procedimiento reproducible. La integración
nativa, las pruebas reales de fallos y las mediciones de recursos siguen pendientes
hasta registrar evidencia de esta revisión exacta. No es una guía de appliance productivo.

## Preparación e instalación versionada

Use una VM Debian 13 desechable con snapshot de recuperación autorizado. El argumento
`--snapshot-confirmed` reconoce ese requisito; no crea ni comprueba un snapshot del
hipervisor. No ejecute el laboratorio privilegiado en Windows, appliances de clientes
ni redes productivas compartidas. Deben estar disponibles Go 1.27.3, las herramientas
y dependencias frontend fijadas por el repositorio, nftables 1.1.3 y las rutas
`/usr/bin/ip`, `/usr/bin/nsenter`, `/usr/bin/setpriv`, `/usr/sbin/nft`. Las dependencias
de compilación pertenecen al entorno de desarrollo; este procedimiento no instala
ni actualiza paquetes del appliance por Internet.

El runtime usa UID/GID numérico **1001**, sin grupos suplementarios. Reserve esa
identidad para el laboratorio. El operador usa UID/GID **1000**, propietario de las
credenciales generadas. Son valores fijos del experimento; no se crean usuarios con
nombre. No reutilice una identidad de servicio perteneciente a otra carga.

Ejecute desde un checkout revisado dentro del laboratorio. Es una primera instalación
en un directorio de versión nuevo, no una actualización automática. Binarios, archivos
web y directorios superiores deben pertenecer a root y no ser escribibles por grupo
u otros. La ruta web fija no debe existir al crear el enlace. Para cambiar de versión,
detenga el laboratorio y revise conjuntamente binario y destino web; los comandos
no sustituyen enlaces existentes.

```bash
export GOTOOLCHAIN=local GOWORK=off
ARTIFACT_VERSION="$(git rev-parse --short=12 HEAD)"
BUILD_DIR=".tmp/admin-lab-build/$ARTIFACT_VERSION"
mkdir -p "$BUILD_DIR"
go build -trimpath -o "$BUILD_DIR/andeiva-admin-lab" ./cmd/andeiva-admin-lab
go build -trimpath -o "$BUILD_DIR/andeiva" ./cmd/andeiva
npm --prefix frontend run build
INSTALL_ROOT="/opt/andeiva-admin-lab/versions/$ARTIFACT_VERSION"
sudo install -d -o root -g root -m 0755 "$INSTALL_ROOT/web"
sudo install -o root -g root -m 0755 "$BUILD_DIR/andeiva-admin-lab" "$INSTALL_ROOT/andeiva-admin-lab"
sudo install -o root -g root -m 0755 "$BUILD_DIR/andeiva" "$INSTALL_ROOT/andeiva"
sudo cp -R frontend/dist/. "$INSTALL_ROOT/web/"
sudo chown -R root:root "$INSTALL_ROOT"
sudo chmod -R go-w "$INSTALL_ROOT"
sudo ln -s "versions/$ARTIFACT_VERSION/web" /opt/andeiva-admin-lab/web
```

No se instala daemon, activación al arrancar, regla de firewall ni forwarding del
host. El binario y la compilación web deben corresponder a la misma revisión revisada.

## Aprovisionamiento, TLS y acceso

```bash
LAB_DIR="$(sudo "$INSTALL_ROOT/andeiva-admin-lab" --provision)"
printf '%s\n' "$LAB_DIR"
sudo "$INSTALL_ROOT/andeiva-admin-lab" --run-lab --snapshot-confirmed "$LAB_DIR"
```

Mantenga abierta esa terminal del supervisor. Use el directorio impreso en una
segunda terminal; se genera bajo `/var/tmp`, no es una ruta arbitraria de estado.
Se crean `admin-a.json`, `admin-b.json` y `viewer.json`, archivos regulares `0600`
propiedad de 1000. Cada cuenta recibe una credencial aleatoria individual de 32 bytes
codificada en 64 caracteres hexadecimales. `accounts.json` conserva sus hashes. No
hay contraseña predeterminada, MFA, acceso de directorio ni gestión productiva de
identidades. No publique credenciales ni copie sus valores en comandos, logs o evidencia.

API y web escuchan únicamente en **https://127.0.0.1:9443**, con TLS 1.3 mínimo.
Abra **https://127.0.0.1:9443/firewall** desde el navegador del laboratorio. Inspeccione
`ca.crt` e impórtelo solo en un perfil desechable de confianza del navegador antes de
conectarse. Retire esa confianza al terminar. CA y certificado del servidor caducan
a las 24 horas; entonces aprovisione otra ejecución desechable. No se escribe una
clave privada de CA. No omita advertencias de certificado ni use opciones TLS inseguras.
El origen exacto es `127.0.0.1:9443`; `localhost` no cumple la validación de Host.
Para un navegador externo a la VM, use un túnel autorizado limitado a loopback hacia
ese origen exacto; no exponga el listener en una interfaz física.

Introduzca el usuario y la credencial de su archivo protegido en el formulario web.
`admin-a` y `admin-b` pueden modificar; `viewer` consulta el estado actual, pero no
modifica ni accede al historial. Las sesiones caducan a los 30 minutos o tras 5 minutos
inactivas. Reiniciar la API invalida sus sesiones en memoria. Fallos de acceso o
auditoría bloquean las operaciones. La interfaz inicia en inglés y tema claro; permite
español, portugués y selección explícita de oscuro. Los cambios son locales hasta
Stage. Distinga Candidate, Running, Startup y último estado efectivo observado.
La actualización del estado es manual.

## CLI oficial y transacciones

Ejecute la CLI como UID 1000, sin `sudo`. Sustituya `<COMMIT>` y `<SUFFIX>` por la
versión instalada y el directorio impreso. Se exige CA explícita; el archivo de
credenciales debe ser regular, del usuario ejecutante, con un único enlace, sin enlace
simbólico y modo 0600. Cada comando inicia y cierra sesión sin guardar el token.
Cambie `--lang en` a `es` o `pt` para localizar los mensajes.

```bash
INSTALL_ROOT="/opt/andeiva-admin-lab/versions/<COMMIT>"
LAB_DIR="/var/tmp/andeiva-admin-lab-<SUFFIX>"
fw() {
  "$INSTALL_ROOT/andeiva" --lang en firewall "$@" \
    --url https://127.0.0.1:9443 \
    --ca-file "$LAB_DIR/ca.crt" \
    --credentials-file "$LAB_DIR/admin-a.json"
}
fw status
fw list
```

Anote el hash Running inicial si desea volver a él. Guarde el JSON siguiente como
`stage.json` en un espacio del operador. Sustituya **2** por el valor exacto actual
`snapshot.generation` de `fw status`: es un ejemplo, no una generación fija. Cada
nueva mutación requiere otra clave de idempotencia. Un reintento de la misma solicitud
conserva la clave y el contenido completos; no reintente conflictos silenciosamente.

```json
{
  "operation": "stage",
  "key": "stage-service-01",
  "expected_generation": 2,
  "config": {
    "schema_version": 2,
    "default_action": "deny",
    "rules": [
      {
        "id": "tcp-service",
        "action": "allow",
        "match": {
          "source": "198.18.0.2/32",
          "destination": "198.18.0.6/32",
          "protocol": "tcp",
          "source_ports": {"from": 1, "to": 65535},
          "destination_ports": {"from": 18080, "to": 18080}
        }
      }
    ]
  }
}
```

```bash
fw stage --request-file stage.json
fw validate
fw commit --confirm-seconds 60
fw status
```

Antes del vencimiento, ejecute `probe tcp 18080` en el supervisor y revise `allowed`.
Confirme solo la revisión que haya comprobado. `fw confirm` obtiene generación y
hash Running actuales y los vincula a la confirmación; un cambio concurrente se
rechaza. Debe confirmar el mismo administrador que hizo commit. Sin confirmación
se restaura la política anterior. El intervalo admitido es 30–120 segundos.
`fw commit` sin intervalo realiza commit sin confirmación pendiente. Ninguna forma
guarda Startup.

```bash
fw confirm
fw save
fw history --limit 50
fw history --before <NEXT_BEFORE> --limit 50
fw rollback --target <EARLIER_REVISION_HASH>
fw status
```

Use paginación solo cuando `next_before` no sea cero; sustituya ambos marcadores
por valores devueltos. El rollback histórico cambia Running, no Startup; ejecute
`save` por separado si esa revisión recuperada debe sobrevivir a un arranque completo.
Una confirmación pendiente bloquea otras modificaciones. Otro administrador no puede
sobrescribir Candidate ajeno ni confirmar su commit. Existen `help`, abreviaturas
inequívocas y `firewall completion`. Un archivo de solicitud permite generación,
clave y destino explícitos; `--request-file -` lee la entrada estándar.

El editor web usa las mismas operaciones stage, validate, commit, confirm, save y
rollback histórico, con revisión de operación y revisión de configuración. El orden
del array determina prioridad. Se admiten hasta 64 IDs únicos. Los CIDR deben ser
IPv4 canónicos; protocolo `tcp` o `udp`; ambos rangos de puertos son inclusivos,
no nulos y hasta 65535. No se aceptan shell, ejecutable, namespace, tabla ni programa
nft arbitrarios.

## Contrato HTTPS tipado

Los cuerpos JSON tienen límite de 65536 bytes. Campos desconocidos/duplicados y
valores inválidos se rechazan. Las escrituras exigen rol administrador, `key` y
`expected_generation`. `X-ANDEIVA-Client` admite `web`, `cli` o `api`: identifica
el origen de auditoría, pero no concede privilegios.

| Método y ruta | Solicitud y respuesta |
|---|---|
| `POST /api/v1/auth/login` | `{username, credential}`; web recibe cookie Secure/HttpOnly/SameSite=Strict e identidad/CSRF; CLI/API reciben además token bearer |
| `GET /api/v1/auth/session` | Identidad, rol, vencimiento y CSRF actuales |
| `POST /api/v1/auth/logout` | Objeto vacío; invalida el token actual |
| `GET /api/v1/firewall` | `{snapshot, effective}`; revisiones y contadores acotados `{id, packets, bytes}` |
| `POST /api/v1/firewall/transactions` | `{operation, key, expected_generation, config?, confirm_for?, target?}`; devuelve estado actual |
| `GET /api/v1/firewall/history?before=0&limit=50` | Solo administrador: `{revisions, audit, next_before}`; límite 1–100 |

`config` solo aparece con `stage`; `confirm_for` es entero JSON en nanosegundos
para `commit` (60 segundos = `60000000000`); `target` contiene el hash Running exacto
para `confirm` o uno del historial para `rollback`. Las otras operaciones son
`validate` y `save`. Las escrituras web requieren Origin exacto y `X-CSRF-Token`;
los clientes bearer envían `Authorization: Bearer TOKEN` sin enviar además cookie
de sesión. No persista tokens en almacenamiento del navegador ni en argumentos.

Los estados efectivos son `verified`, `pending_confirmation`, `recovery_required`
o `unavailable`. Verificado significa coincidencia semántica con Running en la última
lectura, no supervisión continua ni certificación. Los errores devuelven
`{code, request_id}`: entrada inválida 400, identidad denegada 401, operación prohibida
403, conflictos de generación/reintento/pendiente 409 y recuperación no disponible
503. Tras una respuesta ambigua, actualice y revise antes de otra modificación.

## Tráfico aislado y ciclo de vida

Tres namespaces sin nombre contienen origen `198.18.0.2`, gateway y destino
`198.18.0.6`. Los listeners de eco TCP/UDP usan 18080–18082. El gateway administra
solo `inet andeiva_admin`; `src0` y `dst0` fijan la dirección. Direcciones, rutas,
reglas y forwarding del host quedan fuera de la política. El supervisor compara
snapshots del host y una tabla testigo independiente del namespace.

Gana la primera coincidencia; tráfico sin regla e IPv6 se deniegan. Cada paquete
original requiere CIDR, protocolo, puertos e interfaces completos de la política
actual y conntrack original/new o established. Las solicitudes aceptadas reciben
una marca de admisión. Las respuestas necesitan tupla actual invertida, estado
established/reply y esa marca. No hay aceptación global de established. Eliminar,
restringir o anteponer una denegación revoca respuestas coincidentes; un allow actual
para la misma tupla permite intencionalmente una conexión ya admitida. Contadores
suman paquetes/bytes de ambas direcciones y se reinician al reemplazar la tabla.
No son registros por flujo ni capturas de paquetes.

Comandos por entrada estándar del supervisor:

| Comando | Comportamiento |
|---|---|
| `probe tcp 18080`, `probe udp 18080` | Prueba de eco original; puertos válidos 18080–18082 |
| `probe-reverse tcp 18080`, `probe-reverse udp 18080` | Prueba inversa no solicitada, no una respuesta establecida |
| `status` | Comprueba snapshot del host y tabla testigo |
| `kill-api` | Detiene API; conserva helper/política y vencimiento independiente de confirmación |
| `restart-api` | Solo con API detenida; `Boot:false` reanuda Running y recupera conservadoramente pendientes/incertidumbre |
| `kill-helper` | Inyecta fallo: detiene API y cierra todo el laboratorio; se espera error |
| `stop` o EOF | Comprueba host/testigo y limpia procesos/namespaces propios |

El supervisor tiene un máximo de 60 minutos. Use `stop` para cierre normal; una
terminación forzada no reemplaza la limpieza comprobada. `kill-helper` prueba cierre
de emergencia, no continuidad del plano de datos. Volver a ejecutar
`--run-lab --snapshot-confirmed` con el mismo directorio es un arranque completo
`Boot:true` que selecciona Startup guardado. Journal y auditoría permanecen en disco;
conserve la evidencia antes de retirar la VM. Nunca borre el journal para superar
recuperación. Revise `report-<run>.json`, log de operaciones y auditoría con permisos
adecuados: son evidencia local, no salida de API pública. Compruebe limpieza e
invariancia del host antes de declarar éxito. Retire la confianza temporal del navegador.

## Validación y límites

```bash
go test -race ./internal/configpoc ./internal/firewalladmin ./internal/adminauth ./internal/adminapi ./internal/adminclient ./internal/cli ./internal/firewallipc ./internal/firewallnft ./internal/nftengine ./internal/nftpoc ./internal/nftguardian ./cmd/andeiva-admin-lab
go vet ./...
go build ./...
bash scripts/check-firewall-admin.sh
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build
docker build -f frontend/Dockerfile.visual -t andeiva-design-check .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true --shm-size=512m andeiva-design-check
```

Son comandos reproducibles, no una afirmación de ejecución de todos los controles.
Los contenedores compilan/prueban código y UI; este laboratorio privilegiado no es
un despliegue Docker Compose ni EKS/Helm. No se agregan manifiestos de runtime o servicio.

En cada ejecución nativa autorizada registre hash exacto de fuentes/artefactos,
versiones Debian/nft de forma privada, denegación inicial, solicitud/respuesta
permitidas, inversa no solicitada denegada, eliminación/restricción/orden de reglas,
TCP/UDP, separación Candidate/efectivo, rollback, vencimiento durante pérdida de API,
reinicio API, Startup/arranque completo, denegación viewer, generaciones obsoletas,
vencimiento de sesión, cierre por fallo helper, invariancia del host y limpieza.
Mida CPU, RSS máximo, tamaño del journal y duración real. El informe del supervisor
aporta algunos valores; no constituye por sí solo un benchmark de capacidad. Aquí
no se afirma ningún resultado nativo ni objetivo de recursos alcanzado.

Este flujo no implementa IDS/IPS, antivirus, WAF, inspección TLS, filtro DNS, NAT,
VPN, AD SSO, MFA, HA ni instalador de appliance. Sus permisos nunca habilitan tráfico
productivo desconocido para eludir identidad o inspección obligatorias. El POC previo
de catálogo fijo nftables conserva una ruta schema 1 independiente.
