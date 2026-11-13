# Firewall Alpha Preview — Español

Instalación experimental Debian 13 AMD64 en VMware. Las reglas se ejecutan en
namespaces aislados; no protegen el host ni enrutan tráfico productivo. Conserve
un snapshot recuperable y revise los [límites del runtime](../README.md).

## Instalación

La URL raíz de administración abre la consola autenticada. Reglas, Dashboard,
Auditoría, Configuración y Registros de tráfico comparten la sesión y los
contratos transaccionales existentes. Consulte la [guía de la consola](../../../frontend/docs/console-es.md)
para cambios pendientes, confirmación, persistencia en Startup y teclado.
El ancho de banda por interfaz, la atribución por país y la selección de objetos
persistentes siguen sin estar disponibles hasta implementar sus capacidades.


Descargue `firewall-alpha-preview-debian13-amd64` de una ejecución Quality aprobada
del repositorio privado. La retención es de tres días. Compruebe el commit revisado
y `SHA256SUMS`; el checksum no es una firma del proveedor. Transfiera por un medio
autorizado. Las dependencias Debian deben existir; no se descargan automáticamente.

```bash
sha256sum -c SHA256SUMS
sudo dpkg -i ./andeiva-firewall-preview_0.1.0~alpha<BUILD>_amd64.deb
sudo install -o root -g root -m 0644 \
  /etc/andeiva-preview/config.json.example /etc/andeiva-preview/config.json
sudoedit /etc/andeiva-preview/config.json
```

Sustituya `<BUILD>` por la versión descargada. Configure IP/puerto LAN, interfaz
LAN y prefijo explícito del cliente autorizado. `192.0.2.1` y `CHANGE_ME` son
marcadores. El prefijo de origen es independiente de la dirección del servidor;
utilice `/32` si sólo debe acceder una estación. No seleccione WAN en la instalación
inicial. Conserve los nombres de cuentas de servicio del ejemplo.

```bash
sudo /usr/lib/andeiva-preview/andeiva-preview provision
sudo systemctl daemon-reload
sudo systemctl enable --now andeiva-preview.target
sudo /usr/lib/andeiva-preview/andeiva-preview health
sudo systemctl status andeiva-preview.target \
  andeiva-preview-api.service andeiva-preview-helper.service \
  andeiva-preview-namespaces.service --no-pager
```

Provision no reemplaza silenciosamente una instalación existente. El estado
parcial o inválido bloquea el inicio y debe conservarse para diagnóstico.
Identidades, credenciales, certificados y estado persisten durante una actualización.

## Acceso y uso

En el cliente LAN autorizado, confíe explícitamente en la CA de
`/var/lib/andeiva-preview/ca.crt` tras verificar su procedencia. No se modifica
automáticamente la confianza de Windows ni sus rutas. Abra la dirección HTTPS
configurada y `/firewall`; no desactive la verificación del certificado.

Las credenciales iniciales `admin-a`, `admin-b` y `viewer` están en archivos JSON
root-only bajo `/var/lib/andeiva-preview/operator/`. Obtenga la credencial elegida
privadamente desde la consola de la VM; nunca la copie en logs, issues o paquetes
de soporte. Viewer no modifica reglas ni lee historial protegido. No hay MFA productivo.

La CLI instalada es `andeiva`. Un cliente Linux de la LAN utiliza la misma versión,
CA explícita y credencial propiedad del usuario con modo 0600:

```bash
andeiva firewall status --url https://<LAN-IP>:9443 \
  --ca-file ./ca.crt --credentials-file ./admin-a.json
sudo /usr/lib/andeiva-preview/andeiva-preview probe --protocol tcp --port 18080
sudo /usr/lib/andeiva-preview/andeiva-preview probe --protocol udp --port 18080
```

Los comandos `probe` se ejecutan en la VM. Siga la [guía administrativa](../../../internal/firewalladmin/docs/es.md)
para el esquema compartido, Stage, Validate, Commit, Confirm, Save y Rollback,
sustituyendo URL/rutas temporales por las del preview. Las observaciones por regla
son muestras acotadas, no conexiones individuales. Reiniciar API invalida sesiones
y crea un nuevo stream de tráfico.

## Recuperación, actualización y eliminación

Antes de crear los namespaces aislados, el arranque exige diez segundos continuos
sin cambios en las observaciones de red del host, con un límite de treinta segundos.
Esto no garantiza que DHCP haya terminado. Un cambio posterior sigue deteniendo
la preview; no modifica rutas para recuperar el estado inicial. Si la limpieza
encuentra un pin ocupado, consérvelo y siga el procedimiento de reinicio autorizado
descrito abajo. No fuerce el desmontaje ni borre metadata para permitir el arranque.

La prueba nativa opcional requiere Bash y `jq` instalados previamente desde
paquetes Debian offline verificados. Revisa el script y el snapshot primero:

```bash
sudo bash /usr/share/doc/andeiva-firewall-preview/tests/native.sh --ack-isolated-debian13-vm
```

Sin opciones adicionales observa salud, sondas, recursos e invariancia del host.
`--api-failure` interrumpe sólo la API; `--lifecycle` detiene e inicia la preview.
Ambas opciones interrumpen la administración. Los informes privados de root quedan
en `/var/tmp`; no prueban paridad transaccional ni deducen la política esperada
de una sonda exitosa. Compruébalas por separado contra la revisión prevista.

La recuperación automática de API conserva el plazo del helper. Una parada
explícita del servicio puede propagarse al target. La caída del helper cierra todo el preview.
Detenga el target, espere que API, socket, helper y namespaces estén inactivos y
luego inícielo; no suponga que `restart target` es atómico. Un reinicio de servicio
en el mismo boot restaura Running; reiniciar la VM selecciona Startup guardado.
Un journal incierto bloquea la publicación de revisiones.

Si se agota el límite de reinicios de API, API/socket pueden quedar fallidos
mientras target, helper y namespaces conservan la última política verificada.
La administración y las observaciones de tráfico de API no están disponibles;
`target active` no significa disponibilidad. Detenga el target y verifique la
limpieza propia. Si API/socket siguen fallidos, ejecute
`systemctl reset-failed andeiva-preview-api.service andeiva-preview-api.socket`
antes de iniciar explícitamente el target. No borre ni restablezca marcadores
de recuperación de namespaces para eludir otro fallo de limpieza.

Una caída abrupta del daemon de namespaces puede dejar metadata o un pin. Conserve
la evidencia: el preview bloquea su recuperación automática. Un reinicio autorizado
de la VM elimina los recursos volátiles. No borre journal, marcadores ni pins para
eludir la comprobación.

Antes de actualizar, detenga el target y respalde de forma protegida
`/etc/andeiva-preview` y `/var/lib/andeiva-preview`. Verifique el nuevo artifact e
instálelo con `dpkg -i`. El target queda detenido para revisión y debe iniciarse
explícitamente tras comprobar compatibilidad. No se regeneran identidades ni se
borra estado. No hay downgrade automático ni actualizador de appliance firmado.

```bash
sudo systemctl disable --now andeiva-preview.target
sudo dpkg --remove andeiva-firewall-preview
```

Se conservan configuración, credenciales, journal y auditoría. El retiro y borrado
seguro requieren otra acción explícita. No publique esos archivos. Diagnóstico
local: `journalctl -u andeiva-preview-api.service`; disponibilidad: comando health.

Auditoría y journal tienen presupuestos finitos; se cierran ante agotamiento.
Nunca trunque registros protegidos para recuperar acceso. TLS vence al terminar
su validez. Renovación automática, archivado de auditoría, cambios de múltiples
interfaces y Local Service Policy Manager tienen gates independientes. Los
contratos no prueban integraciones. Documente la ejecución nativa antes de validar el preview.

## Versión instalada del producto

Tras iniciar sesión, abre Sistema para consultar la versión ANDEIVA informada
por la API en ejecución. Una compilación sin identidad de paquete se indica como
desarrollo; no se deduce la versión de los archivos del navegador. Este runtime
no tiene catálogo verificado de actualizaciones y muestra disponibilidad no
disponible.

La consulta autenticada desde CLI utiliza el mismo endpoint y permisos:

```sh
andeiva system info --url https://DIRECCION_LAN:9443 --ca-file /trusted/ca.crt --credentials-file /private/operator.json
```

`andeiva --version` informa la compilación local de la CLI, que puede diferir
del appliance conectado. La validación del paquete comprueba que esa identidad
coincida con su versión Debian. Solo se devuelve identidad propia de ANDEIVA,
sin versiones del sistema operativo, kernel ni motores.

### Política conservada al detener la administración

En Debian de laboratorio recuperable, ejecuta el arnés nativo del paquete con
`--ack-isolated-debian13-vm --api-stop`. Detiene API y socket; comprueba procesos,
metadatos y política efectiva del kernel sin cambios; compara seis pruebas reales
TCP/UDP y reinicia la administración. Si falla una comprobación, intenta restaurar
la administración. No valida la intención de la política, migración, reinicio ni routing.