# Guards preparados de ativação v2

[English](ACTIVATION_V2.md) · [Español](ACTIVATION_V2_ES.md)

Este adaptador é preparação, não ativação do runtime. Não altera rotas de
produção, configuração de autenticação, mensagens IPC privilegiadas ou escopo de
namespaces. O runtime real deverá usar o wrapper protegido; Engine sem guard
continua representando apenas simulações.

`PreparedGuardedEngine` reutiliza Engine, ActivationGuard e State/Current/Arm/Confirm
de LeaseAuthority. O callback tipado compara ID, hashes anterior/destino e prazo
original dentro do mesmo bloqueio que executa a recuperação. O IPC
`Client.Recovered` tem outra semântica de barreira de sessão e não é um binding
compatível. Esse callback ainda não possui binding IPC privilegiado.
Não introduz executáveis ou caminhos escolhidos pelo cliente, novos
verbos privilegiados ou bypass administrativo.

O coordenador persiste o intent exato antes de armar o helper. Alterações
imediatas vinculam a lease à operação; commits confirmados usam a lease persistida.
Apply exige o escopo armado exato. A leitura efetiva de todos os componentes
precede Confirm e a publicação do resultado. Respostas perdidas exigem recibo,
lease e revisões exatos; o estado idle sozinho não basta. Commits sem alteração
das regras também estabelecem um recibo de lease.

Retomar uma lease pendente não a rearma nem amplia o prazo, inclusive nos últimos
500 ms. Novas leases continuam exigindo pelo menos 500 ms. O timeout do helper
independe do processo API, sessão ou sujeito.

O rollback usa a recuperação delimitada do guardian após validar lease, revisões e
estado efetivo. Uma confirmação malsucedida pode recuperar-se após comprovar a
reversão do helper: restaura o conteúdo anterior, avança os contadores global e
do domínio, preserva Startup e seleciona atomicamente o resultado, auditoria
vinculada e liberação do pin de origem. O resultado original do commit não muda.

Se o helper já confirmou o destino mas a publicação durável é incerta, bloqueia
escritas sem inventar rollback ou sucesso. A reabertura permanece indisponível
até uma recuperação qualificada separadamente. Staging desconhecido e leases
alheias não são removidos ou reiniciados.

## Validação

Na raiz do repositório, com Go 1.27.4:

```sh
go test -race ./internal/firewalladmin -run '^TestPreparedGuard' -count=1 -timeout=5m
go test -race ./internal/firewalladmin ./internal/configpoc -count=1 -timeout=10m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
```

Os testes Linux usam journals v1 reais, migração a frio explícita, coordenador v2
real, guardian restrito existente e **motores simulados**. Verificam commits
imediatos/confirmados, confirmação tardia, respostas perdidas, aplicação parcial,
leases alheias, timeout independente, reaberturas repetidas e colisão real de
staging após confirmação remota. Não exigem root, regras reais ou conexão ao
appliance. Antes da correção CAS, a validação nativa Debian 13 executou os 10
testes selecionados sem omissões,
como UID 1000 e sem capabilities: tempo 0,586653 s, CPU 0,273888 s e pico de
memória cgroup 12.656.640 B. Usou guardian no mesmo processo, motores simulados
e journals temporários reais. É consumo do processo de teste, não RSS nem consumo
do serviço de produção; não qualifica IPC privilegiado real.

Não qualifica montagem IPC/runtime privilegiada, tráfego nftables real, evidências
de Local Services, aplicação de Startup no boot do SO, garantias físicas de
armazenamento ou falhas de energia. Boot do SO e reinício do processo são casos
distintos; a transição adicional não está implementada aqui. AND-01/02 e os gates
de ativação permanecem abertos.

A qualificação CAS no Debian 13 passou nos 11 testes do adaptador como UID 1000 sem capacidades: 1,196797 s, CPU 0,301658 s e pico de memória cgroup de 10.342.400 B. Os três testes CAS do guardian também passaram: 0,075054 s, CPU 0,026181 s e pico de 7.184.384 B. Foram usados guardian no processo, motores simulados e journals temporários reais; não qualifica IPC privilegiado nem consumo de serviço em produção.
