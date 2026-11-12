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
configuración completa de esquema 4 o 6, según la capacidad del runtime. El esquema4
contiene sólo políticas y no recibe un plan de red inventado. Para esquema6, la CLI
deriva la revisión de red de sus datos validados. La admisión conserva la generación global como cadena decimal
exacta. Stage y Validate no activan tráfico. Commit exige confirmación en 30–120
segundos.

Stage rechaza una Candidate existente. Para reemplazar o descartar su candidata
agrupada, copie su `stage_operation_id` exacto desde status y elija explícitamente:

```sh
cat replacement.json | andeiva configuration replace-candidate --expected-candidate-stage OPERACION_STAGE --request-file - --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration discard-candidate --expected-candidate-stage OPERACION_STAGE --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
```

`replacement.json` contiene `operation: "replace_candidate"` y `config` completo.
La CLI transmite `expected_candidate_stage_operation_id` sin alterarlo y usa la
generación global seleccionada para CAS. Reemplazar conserva la Candidate local;
no evita su prueba de recuperación de acceso. Ninguna operación cambia Running,
Startup ni el tráfico. Una candidata obsoleta sigue siendo legible y nunca se
reemplaza automáticamente. Valide después del reemplazo. Se rechazan abreviaturas
ambiguas como `r`; `rep`, `rol` y `dis` son prefijos distintos.

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

Consulte el historial protegido con `andeiva configuration audit --limit 50` y los mismos parámetros de conexión. `--before SEQUENCE` es un cursor exclusivo. Los límites de consulta no implican un historial completo; `truncated` indica una búsqueda incompleta. Esta lectura no admite ni ejecuta operaciones de configuración.
