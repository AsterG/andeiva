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

A funcionalidade selecionada `configuration.routed-composite.v1` adiciona
projeções schema7 e o namespace `routed`. Stage captura ambas as candidatas;
quando a configuração local é omitida, conserva exatamente sua revisão ativa.
Não sobrescreve candidatas existentes. A identidade do grupo se correlaciona com
a auditoria protegida de Stage, sem fixar o catálogo para sempre. Current inclui
as projeções compostas e `domain_generations` decimais; network é alias de firewall.
Startup permanece independente e pode conservar schema4.

O conjunto não ativa essa funcionalidade. A migração privada a frio verifica
o grafo selecionado, o estado efetivo e a capacidade antes de publicar novos
documentos e auditoria; não altera componentes. Commit, Confirm e Rollback
roteados são recusados antes de Intent até integrar a autoridade agrupada.
Configuração local diferente é recusada antes de reservar enquanto faltar sua
prova de recuperação administrativa. Esses controles não representam ativação
roteada verificada ou disponibilidade para produção.

No Linux executar com `go test -race` os padrões `TestRuntimeServiceV2`,
`TestRuntimeOperations`, `TestRuntimeNetworkInventory` e `TestRuntimeV2`; depois
`go vet` de configpoc/adminapi/previewruntime e `go build ./...`.
