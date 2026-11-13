# Retirada selecionada entre boots do OS

O perfil experimental v4 é separado do reinício de serviço v3. Reiniciar o
serviço mantém Running ou reverte uma operação não confirmada. Reiniciar o OS
seleciona Startup. Nenhum caminho restaura concessão DHCP ou token antigo.

Root deve concluir a parada normal e gravar o recibo v3 de 4096 bytes após drenar
processos e retirar o namespace anterior. O helper v4 recebe FD O_RDONLY de root
e binding de bootstrap ao digest completo e identidade nova real. Verifica BootID
atual do kernel, namespace próprio fora do host e UID/GID de serviço iguais.
BootID e RunID devem mudar. Inodes podem repetir entre boots; cada namespace
continua diferente de seu host.

`RoutedRebootScopeEvidenceV4` separa BOOTTIME da drenagem antiga e observação nova.
Ambos são positivos, sem comparar magnitudes. Deadlines DHCP antigos permanecem
histórico imutável, nunca vigência no novo boot. O mesmo armazenamento selecionado
registra `configuration.routed-reboot-scope.v4`, trabalho/identidade/recibo/readback
exatos e `scope_retired`. Isso não afirma retirada WAN observada, compensação ou
restauração.

G1/R2 completo deve localizar exatamente o trabalho antigo selecionado. Recibo
antigo não permite pular uma instância. `PrepareRebootScopeViewV4` deriva Startup,
Saved e trabalho para montagem confiável do motor. Depois o helper comprova
tabelas/IPv4 vazios, forwarding fechado e listeners reais pelo contrato existente.
`routed_reboot_scope.v4` negocia separado de v3; `reboot_scope` recebe somente
referência de trabalho. Caller não fornece boot, relógio ou prova. Fence persistente
e anchor opaco de attach continuam obrigatórios.

O terminal DHCP antigo é arquivado por reservas/seletor existentes antes de aplicar
LAN do novo Boot. WAN fica sem autoridade de concessão selecionada; apenas uma
concessão nova do novo proprietário permite ativação posterior. Outcomes pendentes
e deadlines UTC originais não mudam. Não libera reservas/boundaries interrompidos
sem prova. Recibos ausentes, parciais ou antigos bloqueiam. Não afirma recuperação
de power-loss, suspensão ou snapshots VM.

Testes usam armazenamento/pools reais, doubles físicos e pipes explícitos: relógio
novo menor, inodes reutilizados, retirada antes de LAN, Startup/Running, trabalho
antigo imutável, deadlines pendentes, G1 corrompido, âmbito incorreto, ausência de
anchor/fence e separação v3/v4. Reboot OS nativo completo, FD root, continuidade
de tráfego e medições CPU/RAM permanecem pendentes.

```sh
go test -race ./internal/configpoc ./internal/firewallipc ./internal/previewruntime -run 'TestRouted(RebootScopeV4|FreshScopeV3)' -count=1
go vet ./internal/configpoc ./internal/firewallipc ./internal/previewruntime
go build ./...
bash scripts/check-config-platforms.sh
```

O recurso Root agrupado compara o BootID atual do kernel com metadata e o recibo
decodificado. Seleciona um único perfil: v3 para o mesmo BootID, v4 quando muda.
Ambos mantêm FD14 exclusivo do helper; a API recebe somente uma flag de capacidade,
sem binding do recibo. Rejeita perfis misturados, binding ausente do helper e
factory API com perfil diferente do bootstrap. A factory v4 usa
`PrepareRebootScopeViewV4(...).Saved` para configurar o motor baseline.

Boot admite inventário local diferente sem serviços somente por
`RoutedNoServicesTransitionV3`: Saved/histórico autenticados, interfaces canônicas
derivadas exatamente da rede e zero definições de serviços nos dois lados. Não
reescreve Saved. Ausência real de listeners e trabalho selecionado continuam
requisitos independentes. Testes cobrem inventário estático e LAN DHCP; rejeitam
histórico ausente, inventário alterado, Saved substituído e estado local inesperado.
Não qualificam reboot OS nativo nem transferência FD root do perfil v4.

```sh
go test -race ./internal/configpoc ./internal/previewruntime -run 'TestRouted(BootNoServicesV3|RetirementBootstrapV[34])' -count=1
```
