# Operaciones de configuración

Los comandos `configuration` requieren un endpoint administrativo v2 autenticado.
El almacén seleccionado determina si admite operaciones de firewall o el grupo
enrutado. Instalar la CLI no migra ni activa una configuración.

Use la CA de confianza y un archivo de credenciales individual, accesible sólo
por su propietario:

```sh
andeiva configuration status --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
cat stage.json | andeiva configuration stage --request-file - --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration validate --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration commit --confirm-seconds 60 --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
```

`stage.json` sigue el contrato tipado `OperationRequestV2`: operación `stage` y
configuración completa de esquema 6. La CLI deriva la revisión de red de sus
datos validados. La admisión conserva la generación global como cadena decimal
exacta. Stage y Validate no activan tráfico. Commit exige confirmación en 30–120
segundos.

Antes de ejecutar, stderr muestra `ANDEIVA_OPERATION_ACCEPTED` y el ID durable.
Ante una interrupción, consulte ese ID antes de enviar otra operación:

```sh
andeiva configuration operation --operation-id OPERACION --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
```

Una operación aceptada puede continuarse expresamente con `execute --operation-id`.
No se repite la ejecución automáticamente ni se sustituye por escrituras v1.
La sesión se cierra incluso ante errores; los espacios creados se cierran tras
resultados terminales. El código de salida 3 indica que sigue aceptada.

Confirm utiliza el ID del Commit original y su revisión compuesta, consultables
en el estado. Save guarda toda Running. Rollback también exige confirmación:

```sh
andeiva configuration confirm --origin OPERACION_COMMIT --target REVISION_COMPUESTA --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration save --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration rollback --target REVISION_COMPUESTA_GUARDADA --confirm-seconds 60 --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
```

La activación del runtime, las reglas efectivas, la compatibilidad del estado
importado y la recuperación necesitan pruebas independientes. Los tests de
transporte y las pantallas con fixtures no las demuestran. No cambie enlaces de
administración con un runtime sin validar. Web/CLI/API comparten los contratos
de admisión y ejecución.
