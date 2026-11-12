# Transporte preparado de operações de configuração

[English](OPERATIONS_V2.md) · [Español](OPERATIONS_V2_ES.md)

Este incremento valida um handler HTTPS privado e o contrato do cliente Go.
O roteador e as capacidades de produção permanecem inalterados: não ativa v2,
não garante retenção, não realiza cutover nem adiciona restrições novas à v1.

Reutiliza as verificações existentes de TLS, host/origem, sessão, CSRF e origem
Web/CLI/API. ServiceV2 verifica a sessão real e o registro canônico de sujeitos
em cada solicitação. Identidades enviadas pelo cliente e cabeçalhos de
encaminhamento não concedem permissões. Viewers não acessam nem alteram o catálogo.

O handler preparado contempla exclusivamente:

- `POST /api/v2/config/operation-namespaces`
- `POST /api/v2/config/operations/admit`
- `POST /api/v2/config/operations/{id}/execute`
- `GET /api/v2/config/operations/{id}`
- `GET /api/v2/config/operations?namespace_id=...&state=...&cursor=...&limit=...`
- `POST /api/v2/config/operation-namespaces/{id}/close`

Essas rotas não são registradas pelo construtor de produção. Não há novo endpoint
de estado ou evidências. Firewall admite stage, validate, commit, confirm, save,
rollback e recover. `revoke` é rejeitado antes da admissão porque ainda não está
implementado no coordenador. Local Services e seu vínculo de provas de acesso
permanecem fora deste transporte.

Os corpos têm limite de 1 MiB. Membros JSON desconhecidos ou duplicados, decimais
não canônicos e identificadores que introduzam caminhos são rejeitados. Novos
uint64 são strings decimais, incluindo ambas as gerações. O resultado histórico
da operação é separado de `current`, que captura geração/lineage global e projeção
do domínio sob o mesmo bloqueio. Páginas vazias ou filtradas também incluem
`current`. Em v2, `snapshot.revoked` contém IDs duráveis de sujeitos retirados,
nunca nomes de usuário importados da v1.

As funções de migração a frio inspecionam fontes v1 bloqueadas sem replay ou
limpeza. Exigem sujeitos, vínculos históricos e fingerprints explícitos; verificam
novamente as duas fontes bloqueadas antes da publicação. Preservam os journals
originais e selecionam armazenamento preparado. Não ativam o runtime nem publicam
Running operacional sem leitura efetiva pelo coordenador.

## Reprodução

Na raiz do repositório, com Go 1.27.4 no Linux:

```sh
go test -race ./internal/adminapi ./internal/adminclient ./internal/configpoc -run '^(TestPreparedOperationsV2.*|TestOperationsV2.*|TestMigrationServiceV2.*|TestServiceV2AtomicObservations|TestServiceV2Observations.*)$' -count=1 -timeout=10m
go test ./cmd/... ./internal/... -count=1 -timeout=10m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
```

Os testes criam journals temporários e HTTPS de loopback com certificado
verificado. Não exigem root ou conexão ao appliance e não alteram namespaces ou
regras reais. O handler utiliza journals v1 reais, migração explícita,
armazenamento v2 real e **motores simulados**. Verifica Commit Confirmed,
confirmação, Save, rollback, resultados históricos/atuais, páginas vazias, RBAC,
propriedade, concorrência e solicitações hostis. O cliente usa fixtures de
contrato identificadas; não comprova um deployment de produção completo.

Validação nativa Debian 13 sem privilégios, processos focais completos:

| Processo | Tempo | CPU | Pico de memória cgroup |
|---|---:|---:|---:|
| Handler HTTPS preparado | 0,997485 s | 0,233278 s | 15.028.224 B |
| Armazenamento/migração | 0,360537 s | 0,138744 s | 12.849.152 B |
| Fixtures do cliente | 0,182327 s | 0,098538 s | 13.606.912 B |

Memória cgroup não equivale a RSS nem ao consumo do serviço de produção. Não
qualifica 5.000 ciclos com motores reais, capacidade física/retenção, falhas de
energia, recuperação de espaço protegido, paridade Web/CLI/API ou cutover. Os
gates de armazenamento e ativação das rotas permanecem pendentes.
