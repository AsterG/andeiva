# Authenticated network inventory

## English

`andeiva system network-interfaces --url https://HOST:PORT --ca-file FILE
--credentials-file FILE` reads the connected appliance's interface inventory.
Use a separately provisioned credential file and the trusted appliance CA.
The command logs out after the request, including when inventory is unavailable.
It does not change addresses, routes or policies. A missing v2 endpoint is an
error; the client never substitutes its own host's interfaces or retries against
a legacy endpoint. Link state is an observation, not a connectivity test.

## Español

El mismo comando consulta las interfaces del appliance mediante HTTPS
autenticado. Use un archivo de credenciales individual y la CA de confianza.
Cierra la sesión incluso si el inventario no está disponible. No cambia
direcciones, rutas ni políticas. Si falta el endpoint v2, devuelve un error sin
sustituirlo por interfaces del cliente ni consultar una ruta heredada. El estado
del enlace no demuestra conectividad.

## Português

O mesmo comando consulta as interfaces do appliance por HTTPS autenticado.
Use um arquivo de credenciais individual e a CA confiável. A sessão é encerrada
mesmo se o inventário estiver indisponível. Não altera endereços, rotas nem
políticas. Se o endpoint v2 não existir, retorna um erro sem substituir os dados
pelas interfaces do cliente nem consultar uma rota legada. O estado do enlace
não comprova conectividade.
