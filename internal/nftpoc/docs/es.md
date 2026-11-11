# Procedimiento para el laboratorio Debian

El alcance probado y las mediciones figuran en el [informe de validación](../VALIDATION.md).
Este procedimiento ejecuta un experimento aislado; no instala el firewall del producto.

Ejecutar únicamente en la VM autorizada de desarrollo Debian 13 AMD64, con snapshot
recuperable y acceso a la consola VMware. No ejecutar la prueba privilegiada en
Windows, WSL, Docker Desktop, runners compartidos ni gateways de producción. No
requiere cambios de Windows, VPN, rutas, forwarding o firewall del host.

## Compilación y pruebas sin privilegios

Usar la versión de Go del repositorio, actualmente 1.27.4. Desde su raíz:

```bash
bash scripts/check-nft-poc.sh
go test -race -count=1 ./internal/configpoc
go vet ./cmd/... ./internal/...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -o andeiva-nft-poc ./cmd/andeiva-nft-poc
sha256sum andeiva-nft-poc
```

Las pruebas unitarias simulan las respuestas de nftables; no realizan operaciones
de red privilegiadas. Transferir el binario por el canal autorizado del laboratorio
y comparar su hash en Debian. No incluir secretos en comandos, código o informes.

## Instalación y ejecución

La VM debe disponer de `/usr/bin/ip`, `/usr/sbin/nft`, `/usr/bin/nsenter` y
`/usr/bin/setpriv`. La ausencia de herramientas bloquea la prueba: el ejecutable
no instala paquetes ni habilita servicios. El binario y las rutas de herramientas
privilegiadas deben pertenecer a root y no admitir escritura de grupo u otros.
El coordinador y las sondas usan un UID/GID sin privilegios; no se instala un
servicio privilegiado permanente.
El fixture requiere la cuenta de laboratorio de confianza con UID/GID 1000.
Si sudo no está disponible, instalar desde una consola root local autorizada.

Inspeccionar una instalación existente antes de reemplazarla. Para una copia nueva:

```bash
sudo install -d -o root -g root -m 0755 /opt/andeiva-nft-lab
sudo install -o root -g root -m 0755 ./andeiva-nft-poc \
  /opt/andeiva-nft-lab/andeiva-nft-poc
sudo /opt/andeiva-nft-lab/andeiva-nft-poc --run-lab --snapshot-confirmed
```

Usar la opción de snapshot solo después de confirmar que la recuperación está
disponible. El ejecutable crea un directorio privado de evidencia bajo
`/var/tmp/andeiva-nft-poc-*` e informa su ruta exacta. Conservar esa ruta y el código
de salida. La existencia del informe o una conexión exitosa no prueban el éxito
de todo el escenario.

La prueba crea tres network namespaces sin nombre, enlaces virtuales y rutas
privadas. Activa forwarding IPv4 únicamente dentro del namespace del gateway y
crea allí la tabla exclusiva `inet andeiva_poc`. Los listeners TCP/UDP 18080, 18081
y 18082 existen solo en el namespace destino. Las interfaces, rutas, forwarding,
tablas nftables y SSH normales de la VM quedan fuera de este entorno.

## Verificación, limpieza y recuperación

Revisar el informe completo: sondas TCP/UDP positivas y negativas, validación,
commit, confirmación/caducidad, compensación, concurrencia, interrupción de proceso,
conservación del estado del host y limpieza. Conservar auditoría, revisión de
código y muestras de recursos en privado. Un listener caído o una ruta rota no
constituyen una prueba de denegación del firewall.

La limpieza normal detiene únicamente los procesos registrados, libera los handles
de namespaces propios y verifica que no queden referencias. No requiere borrar
namespaces por nombre ni eliminar objetos globales. El informe se conserva.

Si aparece propiedad incierta, compensación fallida o fallo de limpieza, detener
nuevas pruebas e inspeccionar desde la consola VMware autorizada. No vaciar reglas,
borrar namespaces arbitrarios, matar procesos ajenos ni modificar rutas corporativas.
Conservar el informe y recurrir al procedimiento conocido de recuperación del
snapshot si no puede identificarse el entorno con seguridad. La muerte del
supervisor, los cortes eléctricos y la recuperación del appliance completo siguen
siendo escenarios separados sin validar.

Para desinstalar, una vez terminado el ejecutable:

```bash
sudo rm -- /opt/andeiva-nft-lab/andeiva-nft-poc
sudo rmdir -- /opt/andeiva-nft-lab
```

No existe una unidad systemd que retirar. Mantener las evidencias hasta su revisión.
Para actualizar, finalizar y limpiar la ejecución anterior, comprobar el nuevo
hash, reemplazar únicamente el binario y usar un journal nuevo. No reutilizar
journals entre versiones de catálogo/compilador sin una migración probada.

Esta prueba IPv4 no es un firewall de producción. La Web, CLI oficial y API de
liveness existentes no incorporan endpoints de administración por esta POC.

## Resultados observados y límites

Dos ejecuciones limpias en Debian aprobaron 15 escenarios cada una: 96 pruebas
TCP/UDP y 112 sondas denegadas continuas. El estado del host coincidió antes y
después; se eliminaron los tres namespaces de prueba. Duración: 59,4–59,8 segundos;
RSS máximo de un hijo: 13.076–13.420 KiB; journal: 189.813–189.816 bytes. No es
la memoria total del appliance ni un benchmark de capacidad. El rollback real
del kernel se probó tras un fallo simulado de otro componente; SIGKILL del
coordinador y vencimiento fueron reales. La pérdida de confirmación del helper
se prueba con simulación; no se validaron su muerte, la del supervisor, cortes
de energía ni transportes Web/CLI/API autenticados de producción. Una confirmación
incierta bloquea nuevas modificaciones. No borrar el journal ni reglas ajenas
para forzar recuperación.
