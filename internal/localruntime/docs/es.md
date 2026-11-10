# Servicios locales: laboratorio Debian aislado

Runner experimental para una VM Debian 13 AMD64 autorizada, con snapshot de
recuperación comprobado y consola disponible. No instala un servicio permanente
ni modifica SSH, firewall, NAT, rutas o interfaces físicas del host. No ejecutar
pruebas de red privilegiadas en runners compartidos.

## Compilación y preparación

En el equipo de compilación, usar el toolchain y lockfile del repositorio:

```sh
go test -race ./internal/localruntime ./internal/localadmin ./internal/localengine ./internal/localobserve
go vet ./cmd/... ./internal/...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o andeiva-local-lab ./cmd/andeiva-local-lab
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o andeiva ./cmd/andeiva
cd frontend
npm ci --ignore-scripts --no-audit --no-fund
npm run build
```

Transferir binarios y `frontend/dist` mediante un medio autorizado y comparar
SHA-256 después de la transferencia. El directorio de binarios debe pertenecer
a root, permitir lectura al usuario API y ejecución al helper. No ubicarlo dentro
del directorio privado de estado. Nunca incluir credenciales en argumentos, logs
o artefactos públicos.

Crear dos cuentas de sistema dedicadas, con UID/GID distintos de cero y entre sí,
shell sin login y sin grupos suplementarios. No reutilizar las cuentas Alpha.
Preparar `/root/lab-config.json`, propiedad root y modo 0600:

```json
{
  "lan_address": "198.51.100.10",
  "lan_interface": "ens34",
  "allowed_cidr": "198.51.100.2/32",
  "api_user": "andeiva-local-api",
  "api_group": "andeiva-local-api",
  "helper_user": "andeiva-local-helper",
  "helper_group": "andeiva-local-helper",
  "web_root": "/opt/andeiva-local-lab/dist"
}
```

Las direcciones son ejemplos: sustituirlas por valores LAN existentes y
autorizados, sin agregarlas al host. TCP 18443 debe estar libre en la dirección
elegida y en loopback; no existe escucha global ni alternativa automática WAN.
Con el binario en PATH, ejecutar como root dentro de la VM:

```sh
andeiva-local-lab provision /var/tmp/andeiva-local-example01 /root/lab-config.json
andeiva-local-lab run --snapshot-confirmed /var/tmp/andeiva-local-example01
```

En la primera preparación, el directorio de estado no debe existir. Repetir
`provision` valida lo existente sin regenerar credenciales ni crear usuarios OS.
Se generan CA/certificado TLS de laboratorio, clave SSH y credenciales de operador
independientes. Proteger `operator/{admin-a,admin-b,viewer}.json` como root 0600.
El certificado dura 24 horas; aquí no hay renovación automática. Confiar en esa
CA únicamente desde un perfil de cliente de pruebas desechable.

## Administración y confirmación

Abrir `https://<dirección-LAN-autorizada>:18443/local-services` e iniciar sesión
con la cuenta provisionada. El tema claro es predeterminado; oscuro es opcional.
La dirección fija de recuperación no se edita desde esta pantalla.

Habilitar HTTPS o SSH, seleccionar interfaz/dirección del inventario aislado,
puerto TCP mayor de 1023 y CIDR de origen explícitos. Preparar Candidate, validar
y aplicar Commit con plazo de confirmación. Save guarda Running en Startup;
no se ejecuta implícitamente al confirmar.

Confirm requiere pruebas autenticadas desde cada binding habilitado. Usar
`probe`, descrito en el README superior, con generation, target y lease de la
transacción pendiente y el mismo administrador. HTTPS verifica CA y SSH la clave
exacta del servidor. Los archivos de prueba son privados y caducan. Introducir
los tokens en la confirmación antes del plazo; no capturar ni registrar el
formulario con tokens. Deshabilitar todos los servicios administrados requiere
sólo la prueba de recuperación que obtiene la interfaz.

```sh
andeiva local-services --help
andeiva local-services status --url https://127.0.0.1:18443 \
  --ca-file /var/tmp/andeiva-local-example01/ca.crt \
  --credentials-file /var/tmp/andeiva-local-example01/operator/admin-a.json
```

Web, CLI y API comparten `/api/v1/local-services`, sus rutas de transacciones e
historial, y `/api/v1/effective-policies`. Usar generación y claves de solicitud
estables. Ante respuesta incierta, consultar estado antes de crear otra operación.
Viewer puede consultar estado/reglas efectivas, pero no escribir ni leer auditoría.
Las reglas generadas se consultan sin edición directa en Políticas efectivas.

## Fallos y limpieza

Desde otra consola root autorizada:

```sh
andeiva-local-lab check /var/tmp/andeiva-local-example01
andeiva-local-lab fault /var/tmp/andeiva-local-example01 api-kill
andeiva-local-lab check /var/tmp/andeiva-local-example01
andeiva-local-lab stop /var/tmp/andeiva-local-example01
```

Probar también `helper-kill` y un cambio pendiente con `api-pause`. Registrar
run, instance, generaciones y hashes antes/después; verificar tráfico real tras
recuperar, no sólo respuestas API. Reset recrea la fixture e interrumpe el
servicio: no demuestra continuidad. Límite: tres resets y 128 probes por
supervisor. Reiniciar el supervisor conserva journal; no borrar estado para
ocultar un fallo.

En el mismo arranque OS se conserva Running confirmado, incluso sin Save. Un
nuevo arranque OS carga Startup. Metadatos de boot ausentes/corruptos con journal
bloquean el inicio. Una revisión no confirmada debe restaurar su predecesora
verificada. Comprobar listeners, reglas, auditoría y tráfico IPv4/IPv6 autorizado
y denegado; distinguir timeout de rechazo TCP y errores TLS, clave o autenticación.

Stop libera únicamente procesos, namespaces y sockets propios. Comparar reglas,
interfaces y rutas del host con la línea base y comprobar servicios instalados.
Conservar estado/evidencia protegidos hasta revisar resultados. Eliminar sólo los
directorios/cuentas creados para esta prueba y sin procesos que los utilicen.
Nunca vaciar el ruleset del host ni borrar recursos de otros experimentos.
