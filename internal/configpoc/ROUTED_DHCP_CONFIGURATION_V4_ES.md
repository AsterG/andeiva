# Configuración con DHCP activo: contrato de lectura v4

Estado: contrato preparado para la fase a de ADR-074. No incorpora productor,
excepción de admisión, API, fábrica ni activación de red. Los bloqueos actuales
de publicación y admisión con DHCP activo permanecen vigentes.

El marcador requerido `configuration.routed-dhcp-configuration.v4` es
persistente y exige los perfiles existentes routed, shared-reader, DHCP v3 y
R2. Los lectores anteriores deben rechazarlo incluso sin su carga opcional.
Sin marcador se mantienen las reglas v3 existentes.

El Work DHCP original, identidad de adquisición, concesión, epoch, revisión
Running original y ámbito R2 físico no cambian. No se altera la generación
original para aparentar que coincide con la configuración posterior.
`preserve` exige igualdad de la revisión canónica **completa** de red entre el
Work original, Before y Target. Cualquier cambio de red, también LAN o DNS, es
`replace`; su lectura se rechaza con `ErrRecovery` hasta implementar el único
contrato compartido de adquisición/retiro de ADR-072/074. No se crea otra fábrica.

La cabecera contiene como máximo dos referencias inmutables: `transition`,
seleccionada antes de Intent/efectos, y `continuation`, recibo final que conserva
la Transition, operación final y configuración final. Transition vincula
exactamente actor, namespace, operación, fingerprint, generaciones, Before,
Target, Work DHCP, SourceSelection y el Work agrupado si corresponde. No apunta
hacia su futuro recibo ni operación final; no se crea un ciclo. La Continuation
anterior se conserva mientras existe una Transition pendiente.

SourceSelection debe contener ya la operación accepted y su admisión física R2.
Su tupla completa debe coincidir con la arista real del selector anterior;
otro selector autoconsistente que apunte al mismo estado se rechaza.
Sólo se admite su Intent exacto. El recibo conserva la operación final inmutable
aunque luego se retire el namespace o reutilice el catálogo circular. G1 visita
las configuraciones, estado fuente, auditoría, Work agrupado e índices mediante
sus límites actuales. No existe otra bitácora, compactador o caché entre lecturas.

La decodificación canónica rechaza campos desconocidos, alias, duplicados, null
en alternativas opcionales y ramas mezcladas. Transition y recibo tienen límite
de 16 KiB. Al comparar una cabecera modificada se materializa un único estado;
el resumen histórico conserva dos hashes. Las reservas no se duplican ni se
comparte crédito de cierre.

Stage/Save de metadatos no pausan el reenvío. El futuro Commit con red idéntica
puede cerrar temporalmente el reenvío, pero conserva la fuente y no solicita
DHCP forzado. Activación, acceso de gestión LAN/consola, Confirm/rollback y
mediciones nativas son criterios pendientes de fases posteriores. Los fixtures
usan reclamaciones R2 reales de bajo nivel, sin demostrar admisión productiva.
Las cifras de Docker no representan recursos del appliance. Este contrato de
lectura no cierra ADR-074 ni el hito de routing.

Contrato completo: [English](ROUTED_DHCP_CONFIGURATION_V4.md).
