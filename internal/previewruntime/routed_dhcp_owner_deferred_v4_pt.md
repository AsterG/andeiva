# Proprietário DHCP diferido v4 — contrato interno

Implementação isolada: revisão independente, integração agrupada, testes nativos
DHCP/privsep/limpeza e medições pendentes. V3 conserva perfil imediato e contrato.
Nenhum perfil é endpoint administrativo público ou versão operacional.

`PrepareRoutedDHCPDeferredOwnerV4` aceita plano DHCP canônico selecionado por root
e descritores retidos. Prepara produtor root, montagens privadas limitadas e
canais; não inicia dhcpcd. WAN estática/NoNetwork não criam produtor e são rejeitados.
Desired.Hash é fixo por incarnation: mudar plano exige seleção root e novo
owner/scope. Não resolve attach dinâmico NoNetwork→DHCP na factory.

`TakeReaderFiles` transfere uma única vez pipes Current e pidfd real do produtor,
sem descritor fictício de aquisição. Binding v4 autenticado por root fixa
LeaseOwner ao PID/start do produtor e boot/run/incarnation/Desired. Helper usa
`NewRoutedDHCPDeferredReaderV4`; API não recebe esses recursos. Root retém outro
pidfd do produtor. V3/v4 rejeitam frames/bindings entre si. O papel separado usa
FD3..10 existentes; atribuição de FDs do helper segue pendente, sem reutilizar
integridade ou recibos de retirada.

Somente root chama `Activate`, uma vez, após provar revisão selecionada,
integrityReady do helper, bootstrap/readback LAN e EmptyListeners independente.
São precondições do supervisor, nunca booleano API. Current não pode ativar,
confirmar, parar ou selecionar plano.

Root envia activate pelo canal privado. O papel inicia `dhcpclient.StartIsolated`,
fixa pidfd/PID/start/parent/net/mount do dhcpcd real e informa sua identidade. Root
verifica independentemente, retém seu próprio pidfd do filho e envia confirm
para essa identidade exata. Somente então Current pode ler evidência confirmada.
Antes retorna indisponibilidade sem lease, epoch ou autoridade R2. Falha termina
a incarnation sem retry/reattach. Ativação limitada a dez segundos; Current
mantém 8 KiB/dois segundos, incluindo espera do lock.

Event.PID é comparado ao dhcpcd real, nunca ao produtor. Helper verifica pidfd do
produtor; o papel verifica vida do filho antes/depois de Current e por vigilância
de 100 ms durante inatividade. Morte do filho invalida a incarnation: não aceita
PID reciclado, start alterado ou outro filho. dhcpcd mantém renovação/rebind
normais. Sequência RPC difere de epoch/sequência do lease; consultas repetidas
conservam fact idêntico e prazo BOOTTIME original. Expiração, JSON/replay/perfil
inválido, EOF e cancelamento nunca usam leases armazenados. Indisponibilidade
observada revoga o epoch anterior.

Stop root antes de ativar não inicia filho. Depois encerra/recolhe filho e
descendentes adotados antes de confirmar. Controle inválido/EOF encerra sem
confirmar sucesso. Falha de início/ativação ou morte abrupta exige drenagem
externa do cgroup completo antes de retirar scope. Morte do líder não basta.

Requisitos root/privsep, caminhos fixos e limites de montagem: [v3](routed_dhcp_owner_v3_pt.md).
Não se afirma NET_RAW isolada, novo motor, privilégios extras API/helper ou mudança
de unidade. Standby consome produtor e montagens só com plano DHCP selecionado.
CPU/RAM/latência e lifecycle nativo pendentes.

Testes sem privilégios com Go 1.27.4 e `GOTOOLCHAIN=local`:

```sh
go test -race ./internal/previewruntime -run TestRoutedDHCP -count=1 -timeout=2m
go vet ./internal/previewruntime
go build ./internal/previewruntime
GOOS=windows GOARCH=amd64 go test -c ./internal/previewruntime -o /tmp/andeiva-owner-v4-windows.test.exe
```

Usam pipes reais e doubles de aquisição/vida do processo, incluindo regressões
v3. Não executam montagens privilegiadas, DHCP ou VM. Não comprovam Docker/EKS
ou readiness nativa. Rollback: remover v4 ainda não integrado e restaurar helpers
v3 do commit pai; sem mudanças na configuração instalada ou estado compartilhado.
