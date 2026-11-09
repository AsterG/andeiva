# Design System de ANDEIVA

[English](../DESIGN_SYSTEM.md) · Español · [Português](design-system-pt.md)

El Design System define la apariencia y los componentes compartidos del frontend.
La página de componentes es un entorno de demostración de la interfaz: sus
ejemplos no administran el appliance, no aplican reglas y no representan métricas
de tráfico reales. La [auditoría](../DESIGN_AUDIT.md) describe los problemas del
frontend anterior y sus causas.

## Temas y preferencia

Light es siempre el tema inicial cuando no existe una elección válida guardada,
aunque Windows o el navegador prefieran Dark. Dark se activa únicamente mediante
una selección explícita. La preferencia utiliza `andeiva.preview.theme` en el
almacenamiento local del navegador; no es una configuración del servidor ni de una
cuenta autenticada.

La inicialización previa al render aplica el tema sobre el elemento `html`.
Los componentes, el fondo del documento y los diálogos consumen ese mismo tema.
Si el almacenamiento no está disponible, la interfaz sigue funcionando: la
selección se mantiene durante la página actual, pero no se promete persistencia
entre sesiones. Los valores desconocidos vuelven a Light. No se deben introducir
consultas a `prefers-color-scheme` para cambiar automáticamente la apariencia.

## Fuentes compartidas

| Recurso | Responsabilidad |
| --- | --- |
| `src/design-system/tokens.css` | Colores semánticos de ambos temas, sombras, espaciado, radios y tipografía |
| `src/design-system/components.tsx` | Componentes reutilizables y semántica de interacción |
| `src/design-system/components.css` | Estilos de los componentes mediante tokens |
| `src/styles.css` | Composición responsive de la aplicación; no una paleta independiente |
| `src/preferences.ts` | Validación y persistencia de la selección |
| `public/theme-init.js` | Aplicación de la preferencia antes del primer render |
| `public/andeiva-logo.png` | Logotipo oficial, sin modificaciones |

Los valores de color pertenecen al archivo de tokens. Los módulos utilizan sus
roles semánticos, como `--color-background`, `--color-surface`,
`--color-text`, `--color-border-control` y `--color-button-primary`.
No deben redefinir esos roles localmente para crear un tercer tema. Un nuevo
estado visual requiere un token común o una extensión documentada de los tokens
existentes, con una combinación válida en Light y Dark.

La paleta corporativa conserva blanco, azul hielo, azul eléctrico, cian y azul
marino. Los colores de acciones, texto y estados pueden ser derivados medidos de
esa identidad. Por ejemplo, el azul eléctrico original con texto blanco no alcanza
4,5:1; el botón primario de Light utiliza un azul derivado para conservar la
legibilidad. Un borde decorativo tenue no sustituye el borde de un control cuando
es necesario para identificarlo.

## Logotipo

El PNG aprobado incorpora un fondo claro. Su superficie de branding permanece
clara de forma deliberada en ambos temas; es una excepción identificada mediante
tokens, de tamaño contenido, y no un fondo blanco accidental del resto de la
interfaz. Se preservan proporción, contenido y bytes originales. No aplicar
`filter`, recoloración, recorte ni deformación para simular una variante Dark.

SHA-256 esperado:

```text
1f79f5ec7f33327c9285c702b63fc5c5a618a28395b2161d594001fdb0199f81
```

## Incorporar un módulo

1. Utilizar las superficies, navegación, botones, campos, filtros, indicadores,
   tablas y diálogos compartidos. No copiar sus estilos dentro del módulo.
2. Separar la composición del módulo de su apariencia semántica. Consumir las
   escalas de espaciado, radios y tipografía; mantener los controles utilizables
   sin depender de un ancho fijo de escritorio.
3. Añadir todos los textos en EN/ES/PT. Usar etiquetas asociadas a los controles,
   instrucciones y errores enlazados con `aria-describedby` y `aria-invalid`
   cuando corresponda. No sustituir una etiqueta por un placeholder.
4. Mantener encabezados y captions de tablas, orden de lectura, navegación por
   teclado, foco visible y devolución del foco al cerrar un diálogo. Los estados
   necesitan texto o símbolos además de color. Las gráficas necesitan leyendas y
   una alternativa textual comprensible.
5. Probar todos los estados del componente en ambos temas: inicial, hover, foco,
   seleccionado, vacío, inválido, deshabilitado y abierto, según corresponda.
6. Actualizar las pruebas y revisar las capturas antes de integrar el cambio.
   No aprobar un componente validado únicamente en Light o únicamente en Dark.

Estas reglas son obligatorias para firewall, NAT, VPN, SD-WAN, QoS, Security
Profiles, IDS/IPS, antivirus, WAF, DNS, logs, filtros avanzados, PCAP,
administración, configuración transaccional y sistema/actualizaciones. Su mención
no implica que esos módulos estén implementados.

## Validación reproducible

Desde la raíz del repositorio, con las versiones de Node y npm indicadas en el
README:

```bash
npm --prefix frontend ci --ignore-scripts --no-audit --no-fund
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build
```

Para las pruebas de navegador y capturas, usar la imagen canónica del repositorio:

```bash
docker build -f frontend/Dockerfile.visual -t andeiva-design-check .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true --shm-size=512m andeiva-design-check
```

`frontend/Dockerfile.visual` fija por digest Playwright 1.65.0 sobre Linux Noble y
Node 24.20.0. CI utiliza esta misma construcción. La imagen ejecuta
`npm run test:e2e`; la configuración inicia el servidor local de pruebas, sin
backend, puertos publicados ni acceso al laboratorio de red. La construcción
necesita descargar sus imágenes y dependencias si no están en caché; la ejecución
de pruebas no tiene acceso a redes externas.

Ejecutar la comparación en ese entorno evita confundir diferencias de fuentes o
renderizado de otro sistema operativo con una regresión del producto. Un navegador
local sirve para investigar, pero no sustituye el entorno de las referencias.

Las referencias visuales están en `e2e/snapshots/`, separadas por viewport, tema y
pantalla. Cuando un cambio visual sea intencional, regenerarlas únicamente en el
entorno canónico y revisar los cambios:

```bash
docker create --name andeiva-design-baselines --network none --cap-drop ALL --security-opt no-new-privileges:true --shm-size=512m andeiva-design-check npm run test:visual:update
docker start --attach andeiva-design-baselines
docker cp andeiva-design-baselines:/work/frontend/e2e/snapshots frontend/e2e/
docker rm andeiva-design-baselines
```

Usar un nombre de contenedor libre. No continuar con la copia si la generación
falla. Revisar las imágenes y el diff; después reconstruir la imagen y repetir
la comparación normal con los dos comandos anteriores. La reconstrucción incluye
las referencias nuevas en la imagen que ejecutará las pruebas.

No regenerar referencias automáticamente para resolver un fallo de CI ni ocultar
las regiones temáticas mediante máscaras. Las comprobaciones incluyen preferencias,
tokens, pares de contraste, accesibilidad automatizada, teclado, idiomas y layouts
de escritorio, tablet y móvil. Las capturas corresponden a renderizados reales.

El objetivo es WCAG 2.2 AA, pero las pruebas automatizadas no certifican por sí
solas conformidad completa ni sustituyen una evaluación con tecnologías de
asistencia. Los resultados ejecutados, versiones y limitaciones deben acompañar
cada revisión. No atribuir una prueba de lector de pantalla a una inspección del
árbol de accesibilidad. Medir el cambio de tamaño del bundle cuando se amplíe el
frontend; los navegadores de prueba no forman parte del runtime del producto.
