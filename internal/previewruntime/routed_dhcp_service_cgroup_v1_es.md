# Ámbito de procesos del servicio DHCP, versión 1

Componente en desarrollo bajo ADR-062. No acredita DHCP WAN, autoriza listeners, abre forwarding ni modifica el contrato público de API, CLI o web.

El supervisor confiable crea un cgroup hijo nuevo por encarnación del servicio antes de iniciar el productor. Sus descendientes heredan la pertenencia. Nunca se adopta un grupo existente. El bootstrap privado exige versión de servicio 1, identidad del kernel dispositivo/inodo y un noveno descriptor heredado (FD 11) abierto para lectura. Los perfiles 3 y 4 conservan su semántica; implementaciones de bootstrap incompatibles se rechazan. Antes de preparar montajes privados, el receptor verifica pin, encarnación exacta, pertenencia y ausencia de otros grupos hijos.

`RetainedServicePin` entrega un duplicado de lectura independiente, propiedad del llamador, con su identidad. El supervisor debe obtenerlo antes del cierre cuando necesite conservar el origen anterior para observación. `Close` mantiene el cierre ordenado existente; después solicita terminación del grupo completo y comprueba `populated=0` con un presupuesto separado de tres segundos antes de retirar ese directorio exacto. Los fallos de identidad o drenaje conservan el error y los recursos del grupo. No hay borrado recursivo ni adopción de procesos arbitrarios.

El drenaje de procesos **no** demuestra ausencia de sockets ni posesión continuada. Un socket transferido puede sobrevivir a su creador. El futuro observador debe conservar el pin anterior y rechazar sockets residuales hasta comprobar su ausencia física completa, sin reutilizar ese origen. Un descriptor de lectura delimita el inventario; no confina al productor root confiable. Este componente no habilita excepciones de listeners.

Cuando no se usa adquisición DHCP, no introduce daemon, timer ni servicio. Adquisición nativa, capacidades, integración de desactivación/readback, revisión de seguridad y mediciones CPU/RAM siguen siendo gates separados. No cambia unidades instaladas, capacidades, red del host, dependencias ni contenedores/Helm. Requiere Linux con cgroup v2, creación limitada al ámbito del supervisor, `CLONE_INTO_CGROUP` y `cgroup.kill`; no afirma compatibilidad con contenedores arbitrarios.

## Validación

Los comandos reproducibles están en la [guía inglesa](routed_dhcp_service_cgroup_v1.md#validation). `TestNativeRoutedDHCPServiceCgroupV1` requiere un laboratorio autorizado y una unidad del supervisor sin uso previo. Verifica ubicación real de hijos, drenaje de varios procesos, rechazo de adopción y supervivencia del pin tras retirar el directorio. No opera sobre la red ni prueba DHCP o propiedad de sockets; las pruebas normales lo omiten. La ejecución nativa y sus recursos deben registrarse antes de declarar acreditación.

## Cambio de fuente

Se agrega un ámbito exclusivo del servicio de adquisición, pin privado obligatorio y API interna para retenerlo. El orquestador mantiene la bitácora compartida.
