# Firewall Alpha Preview — Español

Instalación experimental Debian 13 AMD64 en VMware. Las reglas se ejecutan en
namespaces aislados; no protegen el host ni enrutan tráfico productivo. Conserve
un snapshot recuperable y revise los [límites del runtime](../README.md).

## Instalación

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
