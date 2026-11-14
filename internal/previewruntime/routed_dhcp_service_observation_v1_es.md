# Observación de recursos de adquisición DHCP, versión 1

Componente en desarrollo bajo ADR-062. No autoriza forwarding, reemplaza la recuperación de concesión/R2, demuestra tenencia actual de sockets ni acredita un appliance instalado.

La respuesta privada root/helper `prepare` exige versión de cgroup 1, dispositivo/inodo del kernel y cuatro descriptores SCM_RIGHTS: pipes de petición/respuesta, pidfd del productor y pin de lectura del cgroup. `activate` y `stop` rechazan descriptores y metadatos de preparación. Pares antiguos, datos desconocidos, faltantes o adicionales se rechazan. El contrato público API/CLI/web no cambia.

El helper verifica binding autenticado, cgroupfs, acceso, propietario, identidad, ruta de encarnación exacta, pidfd/inicio y pertenencia del productor. Conserva duplicados independientes. La vista se instala antes de activar; standby exige inventarios vacíos y no consume `Current` antes del ACK root. La activación tipada mantiene el mutex del listener hasta el ACK; después, la observación consulta directamente al lector autenticado, sin volver al mutex del runtime o autoridad.

Se capturan las cuatro tablas TCP/UDP y los inventarios acotados de UDP/AF_PACKET dentro del namespace gateway retenido. Hay dos capturas secuenciales y validación de identidad, concesión y fase antes/después; no se afirma atomicidad del kernel. Cada inventario debe cumplir el perfil completo. Una aparición/desaparición es posible, pero un inodo retenido no puede cambiar silenciosamente cookie o atributos. No hay autoridad por caché ni extensión de plazos.

Sólo se admite un UDP IPv4: UID 0, puerto 68, dirección vigente exacta, inodo correlacionado y cgroup de creación exacto. Dos lecturas físicas deben ubicar esa dirección únicamente en la WAN seleccionada por nombre/MAC. Ifindex 0 no demuestra bind-to-device. Se rechazan wildcard, origen ajeno, direcciones diferentes, UDP adicional y listeners TCP/IPv6.

El perfil soportado del motor mantenido exige RAW/ETH_P_ALL, UID 0, flags 3 e ifindex WAN exacto no nulo. Fuente y medición aislada respaldan espera inicial con cero a dos packet sockets y ningún UDP; con concesión vigente, uno a dos packet sockets y cero o un UDP válido. Dos es el límite del perfil soportado, no un máximo universal del kernel. Otro tipo/protocolo/flags, LAN, ifindex 0 o exceso se rechazan. `packet_diag` no acredita cgroup, tenedor actual ni filtros BPF instalados/bloqueados. El motor privilegiado mantenido y la exclusividad del rol RAW forman parte del TCB; no se afirma contención de un raw socket comprometido por reglas IP. Véase la [fuente mantenida](https://raw.githubusercontent.com/NetworkConfiguration/dhcpcd/v10.1.0/src/if-linux.c).

El retiro revoca primero la vista. El ACK de stop sólo acredita drenaje de procesos. Los pins se liberan después de observar salida en el pidfd y dos inventarios TCP/UDP/packet totalmente vacíos. Residuos o incertidumbre conservan pins y bloquean retiro limpio. Sin servicio DHCP se exige ausencia estricta. No hay adopción de grupos, sockets o procesos.

No agrega workers persistentes, timers, escritor DB, dependencias, servicios ni capacidades. Perfil de unidad, descenso real de UID, adquisición/renovación/retiro integrado, revisión independiente y CPU/RAM siguen pendientes de sus gates. No cambia contenedores/Helm; requiere el ensamblado Linux existente. Comandos en la [guía inglesa](routed_dhcp_service_observation_v1.md#validation). Las pruebas separan modelos de inventario/I/O y SCM_RIGHTS real sin privilegios de una validación nativa del adaptador.

## Cambio de fuente

Observación estricta de recursos de adquisición y retiro condicionado a ausencia física; ampliación sólo del bundle privado de prepare. El orquestador mantiene la bitácora compartida.
