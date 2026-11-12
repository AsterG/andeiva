# Pruebas de tráfico desde un cliente autorizado

`andeiva-traffic-probe` es una herramienta de desarrollo de una sola ejecución, sin
privilegios ni cambios de interfaces, rutas, DNS o firewall. No es la CLI oficial
de administración. `--authorized-lab` declara el alcance autorizado; no autentica
al operador ni acredita que controle el destino.

Siempre exige IPv4 de origen ya asignada al cliente y un destino IPv4/puerto
únicos. Vincula y comprueba el origen y destino reales. No usarla desde el propio
appliance y presentar ese resultado como tráfico de una VM detrás del firewall.

- `tcp`: comprueba una conexión, sin demostrar una regla Allow.
- `udp-echo`: exige respuesta idéntica al reto aleatorio de 32 bytes. Requiere un
  destino de eco autorizado; un servicio UDP normal puede no responder así.
- `dns-a`: resolución IPv4 exitosa con I/O DNS observada al destino explícito.
  Registra intentos UDP/TCP y fallback reales. `resolved_with_dns_io` y
  `resolved_ipv4` no atribuyen los valores al servidor: `resolution_source` siempre
  es `unattributed`. NSS puede recibir NXDOMAIN y luego resolver desde hosts
  local. Una prueba mediante seam controlado simula ese fallback tras NXDOMAIN
  loopback real, sin editar hosts/NSS del sistema. Sin I/O DNS se devuelve
  `dns_not_observed`, sin valores. Máximo 32 IPv4 y 16 intentos; no demuestra
  respuestas A del servidor ni DNSSEC.
- `http-head`: conecta exclusivamente a la IPv4 elegida, usando el hostname URL
  para Host y TLS, sin resolución DNS oculta. No usa proxies, redirecciones,
  conexiones persistentes ni HTTP/2; limita cabeceras a 16 KiB y no lee el cuerpo.

El timeout máximo es 15 segundos. Un timeout, rechazo de conexión o ausencia de
eco **no demuestra Deny**. Hay que correlacionar tuplas y tiempo con contadores,
ruleset y sesiones traducidas reales. El éxito tampoco demuestra NAT o paso por
ANDEIVA. Los bytes son datos tratados por los sockets del proceso, no contadores
por regla o de paquetes de la red.
La hora UTC inicial usa el reloj del cliente, sin acreditar su confianza; el tiempo
transcurrido mide esta ejecución, no el ancho de banda de la red.

HTTPS verifica siempre certificados y hostname, TLS 1.2 o superior. Usa el almacén
de confianza actual del sistema o un `--ca-file` explícito de origen confiable
independiente. Nunca confiar automáticamente en el primer servidor desconocido.
El archivo debe ser absoluto, regular, sin enlaces en ancestros, sin escritura
para grupo/otros, máximo 1 MiB y 256 certificados PEM válidos. En Linux se rechazan
también sustituciones por enlaces/FIFO sin bloqueo. Otros sistemas requieren
calificación nativa; la compilación no basta.

El JSON no incluye credenciales, reto, URL/ruta, query ni errores brutos. Se
rechazan URLs con usuario, query o fragmento. El puerto URL debe coincidir con el
puerto de destino. La ayuda admite `--lang en|es|pt`; las claves/códigos JSON no
cambian con el idioma. Las llamadas del sistema, carga de certificados y lecturas
de archivos no son interrumpibles por contexto: no se promete un límite absoluto
de tiempo o RAM para esas operaciones. No quedan procesos o historial permanente.

Plantillas: sustituir los marcadores por valores del laboratorio autorizado.

```sh
andeiva-traffic-probe --authorized-lab --mode tcp --source-ipv4 IP_CLIENTE --target-ipv4 IP_SERVIDOR --port PUERTO
andeiva-traffic-probe --authorized-lab --mode dns-a --source-ipv4 IP_CLIENTE --target-ipv4 IP_DNS --port 53 --dns-name example.net
andeiva-traffic-probe --authorized-lab --mode http-head --source-ipv4 IP_CLIENTE --target-ipv4 IP_WEB --port 443 --url https://example.net/ --timeout 5s
```

Salida 0: observación positiva; 1: resultado fallido/neutral o fallo de salida; 2:
invocación inválida. No son códigos Allow/Deny. No introducir secretos en argumentos.

Desde el repositorio: `go test -race ./internal/trafficprobe ./cmd/andeiva-traffic-probe`
y `go vet ./internal/trafficprobe ./cmd/andeiva-traffic-probe`. Estas pruebas usan
únicamente listeners temporales loopback, DNS controlado y certificados de prueba;
no acreditan tráfico Internet, NAT o routing real.

Los archivos CA personalizados solo se admiten en Linux. Otros sistemas rechazan `--ca-file` antes de acceder al filesystem con `invalid_ca_file`; HTTPS con confianza del sistema conserva la verificación de certificados. Añadir otro sistema requiere un opener seguro y pruebas nativas.
