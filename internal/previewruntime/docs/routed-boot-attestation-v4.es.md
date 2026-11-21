# Acreditación de arranque tras un corte abrupto de energía

ADR-057 exige un recibo de root que pruebe que el ámbito agrupado anterior se
drenó antes de que otro lo sustituya. Un corte de energía deja íntegro el
registro persistido del ámbito (`grouped-scope-v3`) y deja el slot del recibo
(`grouped-retirement-v3`) vacío o con un ámbito más antiguo. ADR-074 aprobó
una segunda prueba sólo para ese caso.

## Qué hace el lanzador

Antes de liberar el registro del ámbito anterior, el lanzador del sistema lee
la identidad de arranque del kernel directamente de procfs y la compara con el
registro.

- Misma identidad de arranque: no escribe nada. Es un reinicio del servicio y
  el recibo de drenaje ordenado sigue siendo obligatorio.
- Identidad de arranque distinta: el lanzador escribe una acreditación de
  arranque en el slot del recibo. Nombra el ámbito registrado, el resumen de
  ese registro, las cuentas de esta instalación y la identidad de arranque que
  la emitió. Sólo entonces libera el registro y crea un ámbito nuevo.

La acreditación nunca afirma que el ámbito anterior se drenó. Afirma que ese
ámbito pertenece a otro arranque del kernel de la misma instalación.

Si la energía se corta de nuevo durante la recuperación, el almacén
seleccionado puede nombrar todavía el primer ámbito o ya el reemplazo
interrumpido. Por eso el lanzador conserva hasta ocho ámbitos registrados, del
más reciente al más antiguo, y vuelve a emitir la lista en cada arranque
nuevo. Un recibo de drenaje ordenado sustituye la acreditación.

## Qué verifica el helper

El helper recibe el slot como descriptor de sólo lectura vinculado por resumen
al ámbito nuevo. Lee por su cuenta la identidad de arranque del kernel, exige
que la acreditación se haya emitido para esa identidad y para sus propias
cuentas, y exige que el ámbito nombrado por el almacén seleccionado sea uno de
los registrados. Después verifica el historial seleccionado completo y que el
ámbito nuevo está cerrado y vacío, igual que con un recibo de drenaje.

La evidencia persistida con el plan de arranque lleva la marca `boot_attested`
y no tiene tiempo de drenaje. Un almacén con esa evidencia declara la
característica requerida `configuration.routed-boot-attestation.v4`.

## Qué permanece cerrado

Un registro del arranque en curso sin recibo de drenaje, un registro o slot
dañado o manipulado, un registro o acreditación de otras cuentas, un ámbito
que el lanzador nunca registró y un historial seleccionado corrupto mantienen
el servicio cerrado y requieren mantenimiento offline autorizado. Web, CLI y
API no intervienen en esta prueba.

## Límites

Este documento cubre sólo la prueba. Archivar un Commit interrumpido, un
rollback fallido o una sustitución de ámbito inconclusa y seleccionar Startup
para ellos todavía no está implementado; esos estados siguen deteniendo el
arranque. El slot se escribe en su sitio: una escritura truncada por un corte
de energía lo deja ilegible y el servicio cerrado. Si un ámbito iniciado tras
un corte se detiene de forma ordenada antes de que el almacén complete su
recuperación, el recibo de drenaje sustituye la acreditación y el siguiente
inicio se rechaza. Los cortes abruptos en equipo real no están calificados.
