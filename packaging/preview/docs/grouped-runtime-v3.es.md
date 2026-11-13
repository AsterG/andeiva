# Integración del runtime agrupado

El paquete contiene roles internos fijos y el preparador explícito de
integridad. No activa el runtime agrupado ni migra una instalación existente.
Las unidades actuales conservan su modo configurado. No ejecutar manualmente
los roles hijos: exigen descriptores heredados, padre root autenticado y las
credenciales exactas del rol.

La fábrica productiva reutiliza cuentas, auditoría protegida, certificado TLS,
dirección administrativa autorizada y frontend reales. Abre un único escritor
v2 y lectores independientes del helper. No abre otro escritor v1 ni inventa
Startup. Los listeners locales permanecen deshabilitados en este perfil inicial.

Solo la API recibe el socket administrativo; solo el helper recibe su
directorio privado de integridad. Se verifican dirección, interfaz y namespace
del socket, manteniendo TLS y restricciones por origen. HTTPS disponible no
significa configuración validada: el estado de salud exige integridad completa
y lectura efectiva inactiva. Pending o reconciliación no son estados saludables.

## Instalación offline pendiente

El cargador de despliegue y la migración offline todavía no se instalan.
Deberán detener el escritor anterior, verificar su bloqueo liberado y preservar
Running, Startup, Candidate, historial y credenciales. Validarán el esquema
real y las identidades durables; rechazarán estados incompatibles o pendientes.

La preparación utilizará las APIs de migración aprobadas para el almacén v2,
tres perfiles exactos de reservas y activación explícita de contratos agrupados,
plazos absolutos y lector compartido. Las raíces y sus device/inode deberán
quedar fijados con presupuestos de lectura/escritura aprobados, sin aumentos
silenciosos. El preparador sin capacidades creará exclusivamente el marcador
en un directorio 0700 ya perteneciente al helper; no reiniciará ni reparará uno.

Se necesita un namespace aislado nuevo y autorizado, con dos interfaces reales
compatibles. No se convertirá la instancia antigua con direcciones en una
línea base vacía ni se borrarán sus reglas. Ninguna ruta o interfaz del host
se modifica. La validación final exige inspección completa, Startup autorizado
y ruleset real; ante fallos se preservan evidencias y despliegue anterior.

Build reproducible y validación estática del paquete no demuestran migración,
arranque nativo ni tráfico de extremo a extremo.

El arranque y drenaje de los hijos dispone de un límite separado de 45 segundos para la inspección completa de 30 segundos. Los RPC de efectos conservan tres segundos; los plazos persistidos y Boot Started+10 segundos no cambian. La fábrica mantiene la validación completa inicial y no deduce integridad de un socket abierto.

El arranque de API/helper/namespaces heredados se rechaza si existe el marcador root grouped-cutover.json, incluso ilegible, truncado o como enlace colgante. El guard no detiene un escritor ya iniciado: la activación debe detenerlo, recoger sus procesos y conservar su bloqueo previamente. Instalar el paquete no crea el marcador.
