# Runtime preparado de operações

`OpenOperationsRuntimeV2` conecta o helper autenticado v2, o adaptador de prazo
absoluto e o armazenamento selecionado com suas reservas existentes. Não abre um
escritor v1, prepara reservas, migra configuração ou ativa a instalação. O arranque
a frio mantém as verificações de recuperação do coordenador.

A API mantém sessões, TLS, origem, CSRF e RBAC. Novas escritas v1 são recusadas com
`ANDEIVA_V2_OPERATIONS_REQUIRED`. `GET /api/v2/config/current` consulta as projeções
global e firewall reais sob o mesmo bloqueio.

`GET /api/v2/network/interfaces` exige um provedor confiável do namespace do helper.
Sem provedor, responde indisponível; nunca descobre interfaces do host da API como
alternativa. Expõe apenas nome, MAC, MTU, enlace, tipo e endereços/prefixos.

Fechar a API não elimina regras ou namespaces. O helper mantém a política
confirmada e reverte pendências pelo prazo independente. Os testes usam
armazenamento e socket Unix reais com motores simulados; não qualificam redes do
host, instalação permanente ou arranque a frio do grupo roteado.

No Linux executar com `go test -race` os padrões `TestRuntimeServiceV2`,
`TestRuntimeOperations`, `TestRuntimeNetworkInventory` e `TestRuntimeV2`; depois
`go vet` de configpoc/adminapi/previewruntime e `go build ./...`.
