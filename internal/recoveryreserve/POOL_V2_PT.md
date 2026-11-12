# Ciclo de vida preparado das reservas, perfil v2

Esta biblioteca interna adiciona claims exatos, dados imutáveis escritos uma vez e slots prealocados reutilizáveis. Não seleciona configuração, autentica administradores, comprova arquivo canônico nem ativa serviços. As API e bytes R1 permanecem inalterados; cada leitor rejeita o outro formato.

`PrepareV2` exige descritor de diretório privado vazio e papel fixo admission, plan ou emergency. `OpenV2` mantém flock e identidades dos arquivos; o chamador conserva o descritor do diretório. Perfis permitem 1–32 slots com dados alinhados de 4 KiB–1 MiB. Os bancos têm cabeçalhos de 4 KiB e extensões prealocadas separadas. O ciclo não cria arquivos, trunca alocações nem remove caminhos. Preparação parcial é preservada para inspeção.

O perfil R2 de 18 slots deve usar `ClaimClass`: ordinary 0–7, closing 8–15 e system 16–17. Não há empréstimo entre classes ou liberação automática de órfãos. `Claim` genérico é primitiva inferior que a integração de admissão R2 não deve usar. Créditos canônicos de fechamento, catálogo, namespace, bytes e inodes exigem integração própria.

`WriteOnce` vincula dados ao escopo tipado e retorna `BindingV2` imutável. A repetição exata é idempotente; mudança de dados/escopo gera conflito. `ReadBound` exige o binding exato mais recente, sem promover um banco antigo. `InspectClaimed` retorna cópia candidata, não resultado selecionado. Instantes de deadline são normalizados a UTC. Formatação textual de claims/bindings é redigida, mas seu JSON contém metadados internos: excluí-los dos DTO públicos.

`RetireCAS` exige claim/binding exatos e prova estruturada de escopo, finalidade, arquivo e Current/Previous. **O coordenador deve verificar a seleção canônica real, bytes arquivados, dependências e resolução do lease sob seu lock.** A biblioteca valida estrutura, hash do escopo, identidade e CAS; hashes com formato válido não comprovam um arquivo existente. Nunca aceitar provas de retiro em solicitações administrativas. Não há callbacks para store ou autenticação.

O retiro sincroniza e verifica ambos os bancos como retired-held, free-prepared e ready. Somente par ready idêntico permite alocação. Fase interrompida reconhecida só retoma com a prova original exata. Prova antiga não afeta uma nova época. Bancos corrompidos/desconhecidos bloqueiam sem reparo automático ou fallback. Órfãos pré-admissão podem esgotar sua classe após interrupções repetidas.

Sem workers, timers, conexões ou ações de motor. Prealocação não garante metadados, journal, COW, quotas, falhas de mídia, filesystem read-only ou falta de energia. Saída de processo não é teste de perda elétrica. Arquivo protegido, finalidade de leases, replay/seleção v2, isolamento físico e continuidade runtime não são implementados aqui. AND-01/02 continuam abertos.

## Reprodução

Linux, Go 1.27.4 e dependências previamente disponíveis:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/recoveryreserve -count=1 -timeout=4m
go vet ./internal/recoveryreserve
go build ./cmd/... ./internal/...
```

Os testes usam arquivos temporários prealocados reais e provas canônicas de retiro simuladas. Verificam mais de 64 ciclos de reutilização, classes, escopos/épocas, concorrência, falhas, saídas reais de processo, corrupção, identidades/permissões e rejeição cruzada R1/V2. Não qualificam arquivo canônico real, rollback do kernel ou ENOSPC nativo desta implementação v2. Medições de recursos e qualificação nativa de volume finito permanecem pendentes.