# Instalación offline experimental: DHCP inactivo

Añade diez paquetes Debian exactos sobre 41 dependencias ya instaladas en Debian
13 amd64. No habilita DHCP, modifica interfaces/API ni acredita persistencia de
concesiones. Instalación nativa, interrupciones, reinicio y recursos siguen pendientes.

Construcción sin root: entradas públicas exactas de `check/profile/archives.tsv`,
`supply-chain.json`, `source-map.json` y `provenance.json`. `DEB_CACHE` contiene
los 51 DEBs para extraer avisos; solamente diez entran al bundle. `SOURCE_CACHE`
incluye `downloads/<source>/<filename>`, `state/lists/<filename>` y el keyring
Debian autenticado en `keys/debian-archive-keyring.gpg`. `BINARY_LISTS` contiene
InRelease y Packages amd64 sin comprimir. URLs de fuentes en `source-map.json`;
ubicaciones DEB en Packages firmado. No sustituir versiones ni usar apt online
en el dispositivo. La referencia `base-files_13.8+deb13u7_amd64.deb`, SHA256
`fcd42bb5cb63f7bfc4326a92541247872206d60a192fdff65ca14eb83ed408b9`, aporta
textos comunes de licencia; no se instala. Procede del directorio público
`https://deb.debian.org/debian/pool/main/b/base-files/`.

Requisitos de desarrollo: Python 3, gpgv, dpkg-deb, Go 1.27.4 y módulos Go ya
cacheados. No se ejecutan scripts de paquetes durante la construcción.

```sh
python3 packaging/dhcp-server/offline/build.py \
  "$DEB_CACHE" "$SOURCE_CACHE" "$BINARY_LISTS" "$BASE_FILES_REFERENCE" "$NEW_OUTPUT"
go test -race ./packaging/dhcp-server/offline/check
go vet ./packaging/dhcp-server/offline/check
```

Se verifican firmas InRelease, hashes de índices, archivos/versiones exactos y
fuentes. El destino usa sqv y el keyring Debian instalado fijo. Metadata vencida
de security/updates, helpers distintos, arquitectura ajena o baseline diferente
se rechazan. Trixie principal no publica Valid-Until: no se promete frescura
acotada allí. Actualizar el perfil requiere revisión, no desactivar verificaciones.

ID = SHA256 del inventario `SHA256SUMS`; no es una firma de editor. Un operador
autorizado debe confiar independientemente en código e ID revisados. No hay release
público firmado. Preparar el bundle validado bajo root, sin enlaces/ACL/permisos
de escritura ajenos, en `/var/lib/andeiva-dhcp-bundles/ID`; binario ejecutable.

```sh
# Root autorizado del laboratorio: captura sin efectos de instalación.
/var/lib/andeiva-dhcp-bundles/ID/bin/check capture > capture.json
sha256sum capture.json
# Sólo después de revisar handlers/efectos y disponer de recuperación externa:
systemd-run --unit=andeiva-dhcp-offline-install.service --service-type=exec \
  --property=KillMode=control-group --property=SendSIGKILL=yes \
  --property=Delegate=no --property=RemainAfterExit=yes \
  --property=RuntimeMaxSec=720 --property=TimeoutStopSec=15 \
  /var/lib/andeiva-dhcp-bundles/ID/bin/check install ID APPROVED_CAPTURE_SHA256
```

La unidad fija debe estar ausente previamente. Se comprueban MainPID, invocación,
cgroup y política de terminación reales; ejecución directa desde shell rechazada.
Reserva mínima: 512 MiB y 4096 inodos libres, no cota medida de consumo. Root debe
verificar resultado de la invocación actual y cgroup sin procesos antes de recuperar
o limpiar. Antes del recibo de éxito se comprueba que sólo queda el checker. La
captura incluye configuración dpkg/NSS local; repetirla tras cambios del capturador.

La captura exporta metadatos/hashes de scripts/triggers instalados, alternativas,
AppArmor, aliases, cuentas y dpkg; no contenido de cuentas/configuración. Su hash
observado no equivale a aprobación. Se rechazan policy-rc.d existente, Kea previo,
cuenta propia, configuración MySQL o servidor DHCP observado.

APT conserva sus locks POSIX nativos. Fuentes/configuración privadas vacías y
`--no-download --no-remove --no-upgrade --no-install-recommends`. Hook VERSION 3
valida todas las acciones reales y captura bajo lock: sólo diez unpack/configure
nuevos exactos; no extras, reemplazos, bajas ni omisiones. Simulación no autoriza.

Antes de unpack: registro exclusivo fsync, originales protegidos, máscara admin
persistente y policy-rc.d propia deny101 sólo Kea. El perfil inicial **persistente**
sustituye la propuesta anterior de overlay privado: jamás reemplaza un hook ajeno.
Ambas guardias permanecen incluso tras éxito/fallo. Scripts revisados sí producen
cambios reales de cuentas, configuración, alternativas, AppArmor y triggers.

Éxito exige paquetes exactos, anteriores intactos en versión/estado, audit limpio,
links de arranque deshabilitados, unidad enmascarada/inactiva y ausencia observada
de procesos Kea/UDP67. No demuestra ausencia transitoria AF_PACKET: falta prueba
nativa. Log principal limitado a 4 MiB; overflow falla. Se elimina sólo el log
terminal duplicado de APT, no historial/audit. Otros logs/disco/inodos/CPU/RAM pendientes.

Fallo: conservar `/var/backups/andeiva-dhcp-offline`, máscara y policy. Reintento
rechaza operación retenida. Sin resume, limpieza automática, purge, downgrade,
borrado de cuentas/bibliotecas compartidas. Timeout no prueba drenaje de hijos.
Revisar procesos/dpkg/registros/backups antes de recuperar; no restaurar status
antiguo sobre dpkg vivo. Originales+hashes no son rollback completo del filesystem.
Upgrade y rollback de concesiones persistentes necesitan pruebas separadas.

Inventario diez+41 no es SBOM completo. Avisos originales/textos comunes Debian
conservados; conclusiones legales NOASSERTION. Apache-2.0 sólo código ANDEIVA.
Se incluyen siete versiones fuente con cambios Debian y hashes para acompañar
entregas binarias autorizadas; no se instalan/compilan. Disponibilidad de fuentes
no implica clearance legal ni cumplimiento completo de redistribución.
