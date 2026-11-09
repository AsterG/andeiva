# Paquete experimental para Debian

[English](en.md) · [Português](pt.md)

Este procedimiento corresponde a `andeiva-experimental` versión `0.0.0~exp1` en
una VM de desarrollo Debian 13 amd64. Empaqueta la CLI informativa y el servidor
de salud. No instala firewall, autenticación, VPN, inspección de tráfico, agente
privilegiado de administración, actualizaciones `.sgu` firmadas ni recuperación
A/B. El frontend sigue siendo una página de desarrollo separada; este servicio
no ofrece administración web.

Los comandos describen el contrato del paquete. Una ejecución satisfactoria en el
laboratorio debe registrarse contra la compilación exacta; esta guía no afirma que
esas pruebas hayan pasado.

## Requisitos y roles

Compile con un usuario ordinario en una estación Linux confiable que ya disponga
de la revisión fuente, Bash, Git, Go 1.27.3, `dpkg-deb`, `sha256sum` y las utilidades
habituales de compilación. No se necesita Docker como runtime. Si falta un
requisito, existe un bloqueo; no haga descargar dependencias automáticamente a la VM.

La VM ya debe disponer de systemd como gestor del sistema activo, las dependencias
`systemd (>= 257)` e `init-system-helpers (>= 1.69~)`, Bash, `dpkg`, `sha256sum`,
`ps` y `ss`. La sonda de salud no necesita curl ni Python.

La instalación, el control del servicio y la retirada requieren una consola root
expresamente autorizada en la VM Debian 13 aislada. Confirme su identidad, snapshot
y consola de recuperación antes de cambiar nada. Estos pasos no corresponden al
host Windows ni a un gateway operativo. No incluya credenciales en comandos,
archivos ni logs compartidos.

El mínimo previsto del appliance es 2 GB de RAM y 64 GB de capacidad de disco.
Este paquete no certifica ese perfil ni un instalador del appliance. Registre RAM,
espacio libre y almacenamiento reales por separado; capacidad no es espacio libre.

## Compilar y transferir

Desde la raíz de las fuentes confiables, con un usuario distinto de root:

```bash
set -euo pipefail
umask 077
test "$(id -u)" -ne 0
export GOENV=off GOTOOLCHAIN=local GOPROXY=off GOTELEMETRY=off
test "$(go env GOVERSION)" = go1.27.3
out_dir=$(mktemp -d "${TMPDIR:-/tmp}/andeiva-debian-package.XXXXXX")
bash packaging/debian/build.sh '0.0.0~exp1' "$out_dir"
cd -- "$out_dir"
sha256sum --check --strict SHA256SUMS
sha256sum SHA256SUMS
```

En WSL, `OUT_DIR` debe estar en el filesystem Linux, no en `/mnt/c` ni otro
directorio montado desde Windows. El control del paquete necesita permisos Unix
reales; DrvFS puede informar modo `777` para el directorio y provocar que
`dpkg-deb` rechace la compilación. Mantenga `TMPDIR` en Linux o sin definir. Si
aborta la compilación, no considere el directorio un artefacto terminado ni relaje
las comprobaciones de permisos.

Las salidas son `andeiva-experimental_0.0.0~exp1_amd64.deb`, `SHA256SUMS` y
`build-info.txt`. El constructor acepta un tercer argumento opcional
`SOURCE_DATE_EPOCH` o la variable de entorno del mismo nombre; de lo contrario usa
la fecha del commit fuente. Conserve la revisión y la información de compilación.
Para otra versión experimental, use la misma interfaz con una versión elegida
explícitamente, como `0.0.0~exp2`, y un directorio de salida nuevo.

Transfiera la salida completa mediante transferencia SSH autorizada, un medio
local o una carpeta compartida ya aprobada. Verifique la identidad del host SSH
por un canal confiable; nunca desactive esa comprobación. No habilite servicios
nuevos de compartición, SSH root, redirecciones de puertos ni cambios de red del
host o de la VPN para este procedimiento.

Registre el SHA-256 de `SHA256SUMS` por un canal independiente confiable. En la VM,
desde el directorio transferido, compare ese valor antes de verificar el paquete:

```bash
sha256sum SHA256SUMS
sha256sum --check --strict SHA256SUMS
```

Un checksum detecta cambios de bytes; no autentica al publicador cuando checksum
y paquete proceden de la misma fuente no confiable. Son artefactos experimentales
compilados localmente, no releases firmadas. Deténgase si no puede establecer
confianza o integridad. Conserve el paquete verificado para las pruebas de retirada
y reinstalación.

## Instalar en la VM

Abra la consola root autorizada en la VM y entre en el directorio del bundle
verificado. Revise el sistema y los metadatos: Debian 13, `amd64`, paquete
`andeiva-experimental`, versión `0.0.0~exp1`.

```bash
set -euo pipefail
umask 077
test "$(id -u)" -eq 0
cat /etc/os-release
test "$(dpkg --print-architecture)" = amd64
package_file="$PWD/andeiva-experimental_0.0.0~exp1_amd64.deb"
test -f "$package_file"
dpkg-deb --field "$package_file" Package Version Architecture
dpkg --install "$package_file"
dpkg-query --show --showformat='${Package} ${Version} ${Status}\n' andeiva-experimental
```

El paquete instala `/usr/bin/andeiva`, `/usr/lib/andeiva/andeiva-api`,
`andeiva-api.service` y el conffile `/etc/andeiva/andeiva-api.env`. El servicio
utiliza una identidad dinámica sin privilegios y `/run/andeiva-api` para archivos
temporales de ejecución; ese directorio no almacena datos persistentes de aplicación.
El helper de readiness acotado se instala en `/usr/lib/andeiva/wait-ready`; las
licencias e información de compilación quedan en `/usr/share/doc/andeiva-experimental`.

La configuración inicial solicita habilitar e iniciar el servicio. La política
de servicios de Debian, una unidad deshabilitada por el operador o una máscara
pueden diferir el arranque. Que `dpkg` termine de configurar el paquete no demuestra
que el servicio esté activo. Revise política y estado; si no hay autorización para
activarlo, deténgase sin eludir la restricción.

## Configuración, salud y control del servicio

El conffile predeterminado contiene `ANDEIVA_LISTEN_ADDR=127.0.0.1:4000`. Mantenga
el servicio sin autenticación en loopback. No lo exponga mediante una dirección
LAN, escucha wildcard o proxy inverso. Si una prueba autorizada cambia el puerto,
elija una dirección loopback numérica desocupada y ajuste todas las sondas siguientes.
No ejecute el conffile como script de shell. Reinicie el servicio tras una edición
aprobada.

```bash
cat /etc/andeiva/andeiva-api.env
systemctl is-enabled andeiva-api.service
systemctl is-active andeiva-api.service
andeiva help
andeiva --lang en status
andeiva --lang es status
andeiva --lang pt status
probe_addr=127.0.0.1:4000
ANDEIVA_LISTEN_ADDR="$probe_addr" /usr/lib/andeiva/andeiva-api --healthcheck
```

La sonda sale con código 0 y sin salida al recibir la respuesta de salud exacta;
no utiliza los proxies configurados. El endpoint devuelve `{"status":"ok"}` solo
para indicar que el proceso responde. La CLI
declara expresamente que las funciones del gateway no están implementadas. Un
comando desconocido, como `andeiva config`, sale con código 2; no configura un gateway.

Use estas operaciones únicamente sobre la VM identificada:

```bash
systemctl stop andeiva-api.service
systemctl start andeiva-api.service
systemctl restart andeiva-api.service
systemctl status --no-pager andeiva-api.service
journalctl --unit andeiva-api.service --boot --no-pager
```

`stop` afecta a la ejecución actual, no a la habilitación de arranque. Para dejarlo
detenido también tras reiniciar, use `systemctl disable --now andeiva-api.service`.
Para recuperar el inicio cuando esté autorizado, use
`systemctl enable --now andeiva-api.service`. Una máscara deliberada requiere revisión
de su responsable; la instalación no debe retirarla silenciosamente.

## Actualización y reversión explícita

Antes de actualizar, conserve el `.deb` anterior verificado, su manifiesto y una
copia del conffile en un directorio persistente de respaldo aprobado por el operador.
No guarde recuperación bajo `/run`. Asigne a `next_deb` la ruta absoluta del nuevo
paquete después de verificar su propio manifiesto de checksums confiable. Compruebe
nombre, arquitectura y versión deseada antes de instalar:

```bash
test -f "$next_deb"
dpkg-deb --field "$next_deb" Package Version Architecture
dpkg --install "$next_deb"
dpkg-query --show --showformat='${Version}\n' andeiva-experimental
```

El archivo de entorno es un conffile de Debian. Revise cualquier pregunta sobre
su sustitución, sin forzarla; preserve la configuración local loopback deseada.
Las actualizaciones respetan la deshabilitación, máscara y política local del
servicio. Si estaba activo, verifique después reinicio, salud y configuración.
Si estaba deshabilitado o enmascarado, compruebe que el paquete no lo activó.

La reversión es un downgrade explícito del paquete, no recuperación atómica del
sistema. Asigne a `rollback_deb` la ruta absoluta del paquete anterior confiable y
verifique otra vez su manifiesto. Confirme la compatibilidad del formato de
configuración y después ejecute:

```bash
test -f "$rollback_deb"
dpkg-deb --field "$rollback_deb" Package Version Architecture
dpkg --install "$rollback_deb"
dpkg-query --show --showformat='${Version}\n' andeiva-experimental
```

Repita las comprobaciones de salud y estado. Si falla un script del paquete o la
configuración es incompatible, deténgase, conserve el diagnóstico y utilice el plan
aprobado de recuperación de la VM. Este paquete no proporciona migraciones DB,
particiones de rollback ni una cadena de actualizaciones offline firmadas.

## Retirar, reinstalar y purgar

La retirada detiene el servicio y elimina los ejecutables del paquete, conservando
el conffile. Verifique esa conservación; no borre configuración ajena ni datos del usuario:

```bash
dpkg --remove andeiva-experimental
test -f /etc/andeiva/andeiva-api.env
test ! -e /usr/bin/andeiva
test ! -e /usr/lib/andeiva/andeiva-api
```

Para reinstalar, verifique otra vez paquete y manifiesto, ejecute
`dpkg --install "$package_file"` y repita las comprobaciones de servicio, conffile
y salud. Revise la configuración conservada; no suponga que tiene valores predeterminados.

Purgar es una decisión explícita distinta que elimina el conffile del paquete:

```bash
dpkg --purge andeiva-experimental
test ! -e /etc/andeiva/andeiva-api.env
```

La purga no es un reset de fábrica. No borra respaldos del operador, archivos ajenos
del usuario ni el historial del journal del sistema. No requiere limpieza recursiva.

## Verificación tras reinicio y observación de recursos

Después de instalar con autorización, registre habilitación, escucha efectiva,
hash de configuración y una muestra del proceso:

```bash
systemctl is-enabled andeiva-api.service
systemctl is-active andeiva-api.service
sha256sum /etc/andeiva/andeiva-api.env
systemctl show andeiva-api.service --property=MainPID,DynamicUser,RuntimeDirectory,MemoryCurrent,CPUUsageNSec
api_pid=$(systemctl show andeiva-api.service --property=MainPID --value)
test "$api_pid" -gt 0
ps -p "$api_pid" -o pid=,uid=,rss=,pcpu=,etime=
ss -ltnp
```

Si no está disponible la contabilidad, regístrela como no disponible. Estas muestras
no son benchmarks de throughput, capacidad ni reposo prolongado. Conserve los
resultados de forma privada y retire datos de procesos o direcciones ajenos antes
de compartirlos.

Solo con aprobación explícita para reiniciar esta VM y un snapshot de recuperación
verificado, ejecute `systemctl reboot` desde su consola. Vuelva por la consola
aprobada, repita las comprobaciones de estado/hash/salud y confirme que la escucha
sigue en loopback. El directorio runtime puede recrearse y el UID dinámico cambiar;
ninguno es identidad persistente. Registre el resultado real posterior al arranque;
un enlace de habilitación no demuestra que el servicio inició correctamente.

Si faltan dependencias, transferencia, recuperación por consola o autorización,
deje el procedimiento pendiente. Ante fallos de escucha, inicio o salud, revise
el journal de este servicio sin ampliar exposición ni desactivar protecciones.
Registre revisión exacta, hashes, operaciones, códigos de salida y limitaciones.
Esta prueba no valida capacidades de seguridad del appliance ni completa la fase.

`ANDEIVA_SERVICE_IDENTITY_CONFLICT` o `ANDEIVA_INSTALL_PATH_CONFLICT` indican un
conflicto con una cuenta, grupo o ruta existente. Consérvelos y revise su propiedad;
no borre archivos ni cuentas ajenos para lograr la instalación.
`ANDEIVA_SERVICE_DEFERRED` exige revisar la política y el estado real del servicio.

## Pruebas reproducibles del paquete

Ejecute las comprobaciones del archivo en la estación Linux confiable, desde la
raíz de las fuentes. Necesitan Python 3 en esa estación, no en la VM. Asigne a
`exp1_deb` y `exp2_deb` las rutas absolutas de los paquetes verificados
`0.0.0~exp1` y `0.0.0~exp2`. Los directorios de resultados deben ser nuevos y estar
fuera del árbol fuente:

```bash
checks_dir=$(mktemp -d "${TMPDIR:-/tmp}/andeiva-package-checks.XXXXXX")
bash packaging/debian/tests/static-package.sh --package "$exp1_deb" --evidence-dir "$checks_dir/exp1"
bash packaging/debian/tests/static-package.sh --package "$exp2_deb" --evidence-dir "$checks_dir/exp2"
sha256sum -- "$exp1_deb" "$exp2_deb"
```

La suite de ciclo de vida es una alternativa a la instalación manual anterior:
requiere una VM VMware Debian 13 amd64 aislada, sin registro previo del paquete,
unidad, rutas del paquete ni política de inicio de servicios, y con los puertos
4000 y 44001 libres. Rechaza estado existente; nunca borre datos ni políticas
ajenos para superar el preflight. Exige autorización root y snapshot de recuperación
confirmado.

En la VM, asigne a `exp1_deb` y `exp2_deb` las rutas de los paquetes transferidos,
a `exp1_sha256` y `exp2_sha256` los hashes registrados por la estación confiable y
a `snapshot_ref` la referencia real del snapshot confirmado. Use un directorio
padre existente propiedad de root para resultados nuevos. Desde la raíz confiable
de las fuentes de prueba:

```bash
run_evidence="/var/tmp/andeiva-native-run-$(date -u +%Y%m%dT%H%M%SZ)"
bash packaging/debian/tests/vm-lifecycle.sh run \
  --install-deb "$exp1_deb" --install-sha256 "$exp1_sha256" \
  --upgrade-deb "$exp2_deb" --upgrade-sha256 "$exp2_sha256" \
  --evidence-dir "$run_evidence" --snapshot-ref "$snapshot_ref" \
  --lab-ack ANDEIVA-ISOLATED-LAB
```

La suite instala, cambia su propio conffile, actualiza, revierte explícitamente,
comprueba estado deshabilitado/enmascarado, termina deliberadamente el proceso del
servicio, prueba configuración inválida y recuperación, y retira, purga y reinstala
su paquete de prueba. Una ejecución correcta termina con ese paquete purgado. Ante
un fallo detiene el servicio propio y conserva estado para diagnóstico. No reinicia
la VM, modifica redes, instala dependencias ni opera snapshots. Aquí no se presupone
ningún resultado.

La comprobación del reinicio real es separada y también parte de una VM limpia autorizada:

```bash
reboot_evidence="/var/tmp/andeiva-native-reboot-$(date -u +%Y%m%dT%H%M%SZ)"
bash packaging/debian/tests/vm-lifecycle.sh prepare-reboot \
  --install-deb "$exp1_deb" --install-sha256 "$exp1_sha256" \
  --evidence-dir "$reboot_evidence" --snapshot-ref "$snapshot_ref" \
  --lab-ack ANDEIVA-ISOLATED-LAB
```

Registre ruta de resultados y referencia del snapshot. La preparación deja el
paquete instalado; no acredita el resultado posterior al arranque. Realice el
reinicio de la VM autorizado por separado desde su consola. Al volver, restaure
`reboot_evidence` y `snapshot_ref` con los valores registrados y regrese a la raíz
de las fuentes de prueba:

```bash
bash packaging/debian/tests/vm-lifecycle.sh verify-after-reboot \
  --evidence-dir "$reboot_evidence" --snapshot-ref "$snapshot_ref" \
  --lab-ack ANDEIVA-ISOLATED-LAB
bash packaging/debian/tests/vm-lifecycle.sh cleanup-reboot \
  --evidence-dir "$reboot_evidence" --snapshot-ref "$snapshot_ref" \
  --lab-ack ANDEIVA-ISOLATED-LAB
```

La verificación exige un boot ID realmente distinto y archivos propios sin cambios;
la limpieza retira el paquete de prueba. Mantenga resultados privados y conserve
los fallos. Si una comprobación rechaza propiedad o estado, revíselo sin eludirla.
