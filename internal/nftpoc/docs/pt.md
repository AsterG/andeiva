# Procedimento para o laboratório Debian

Trabalho em andamento: o procedimento privilegiado ainda não foi validado no
Debian. Não executá-lo até concluir a proteção contra confirmação incerta e a
revisão de segurança indicadas no README do experimento.

Executar somente na VM autorizada de desenvolvimento Debian 13 AMD64, com snapshot
recuperável e acesso ao console VMware. Não executar o experimento privilegiado no
Windows, WSL, Docker Desktop, runners compartilhados ou gateways de produção. Não
são necessárias alterações no Windows, VPN, rotas, encaminhamento ou firewall do host.

## Compilação e testes sem privilégios

Usar a versão de Go do repositório, atualmente 1.27.3. A partir da raiz:

```bash
go test -race -count=1 ./internal/configpoc ./internal/nftpoc
go vet ./cmd/... ./internal/...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -o andeiva-nft-poc ./cmd/andeiva-nft-poc
sha256sum andeiva-nft-poc
```

Os testes unitários simulam respostas do nftables; não realizam operações de rede
privilegiadas. Transferir o binário pelo canal autorizado do laboratório e comparar
seu hash no Debian. Não incluir segredos em comandos, código ou relatórios.

## Instalação e execução

A VM deve fornecer `/usr/bin/ip`, `/usr/sbin/nft`, `/usr/bin/nsenter` e
`/usr/bin/setpriv`. Ferramentas ausentes bloqueiam o experimento: o executável não
instala pacotes nem habilita serviços. O binário e os caminhos das ferramentas
privilegiadas devem pertencer a root, sem permissão de escrita para grupo ou outros.
O coordenador e as sondas usam UID/GID sem privilégios; nenhum serviço privilegiado
permanente é instalado.

Inspecionar uma instalação existente antes de substituí-la. Para uma cópia nova:

```bash
sudo install -d -o root -g root -m 0755 /opt/andeiva-nft-lab
sudo install -o root -g root -m 0755 ./andeiva-nft-poc \
  /opt/andeiva-nft-lab/andeiva-nft-poc
sudo /opt/andeiva-nft-lab/andeiva-nft-poc --run-lab --snapshot-confirmed
```

Usar a opção de snapshot somente depois de confirmar a disponibilidade da
recuperação. O executável cria um diretório privado de evidências em
`/var/tmp/andeiva-nft-poc-*` e informa o caminho exato. Guardar esse caminho e o
código de saída. A existência do relatório ou uma conexão bem-sucedida não
comprovam o sucesso de todo o cenário.

O experimento cria três network namespaces sem nome, links virtuais e rotas
privadas. Habilita o encaminhamento IPv4 somente dentro do namespace do gateway e
cria ali a tabela exclusiva `inet andeiva_poc`. Os listeners TCP/UDP 18080, 18081 e
18082 existem somente no namespace de destino. Interfaces, rotas, encaminhamento,
tabelas nftables e SSH normais da VM ficam fora desse ambiente.

## Verificação, limpeza e recuperação

Revisar o relatório completo: sondas TCP/UDP positivas e negativas, validação,
commit, confirmação/expiração, compensação, concorrência, interrupção de processo,
preservação do estado do host e limpeza. Guardar auditoria, revisão do código e
amostras de recursos em privado. Um listener indisponível ou uma rota quebrada não
comprovam bloqueio pelo firewall.

A limpeza normal encerra somente os processos registrados, libera os handles dos
namespaces próprios e verifica a ausência de referências. Não exige excluir
namespaces por nome ou objetos globais. O relatório permanece para inspeção.

Se houver propriedade incerta, compensação malsucedida ou falha de limpeza,
interromper novos testes e inspecionar pelo console VMware autorizado. Não limpar
rulesets, excluir namespaces arbitrários, encerrar processos de terceiros ou
alterar rotas corporativas. Preservar o relatório e usar o procedimento conhecido
de recuperação do snapshot caso o ambiente não possa ser identificado com
segurança. Morte do supervisor, falhas de energia e recuperação do appliance
completo continuam sendo cenários separados, ainda não validados.

Para desinstalar, depois que o executável terminar:

```bash
sudo rm -- /opt/andeiva-nft-lab/andeiva-nft-poc
sudo rmdir -- /opt/andeiva-nft-lab
```

Não há unidade systemd para remover. Manter as evidências até sua revisão. Para
atualizar, concluir e limpar a execução anterior, verificar o novo hash, substituir
somente o binário e usar um journal novo. Não reutilizar journals entre versões do
catálogo/compilador sem uma migração testada.

Este teste IPv4 não é um firewall de produção. A Web, a CLI oficial e a API de
liveness existentes não recebem endpoints de administração por este experimento.
