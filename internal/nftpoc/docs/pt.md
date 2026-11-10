# Procedimento para o laboratório Debian

O escopo testado e as medições constam no [relatório de validação](../VALIDATION.md).
Este procedimento executa um experimento isolado; não instala o firewall do produto.

Executar somente na VM autorizada de desenvolvimento Debian 13 AMD64, com snapshot
recuperável e acesso ao console VMware. Não executar o experimento privilegiado no
Windows, WSL, Docker Desktop, runners compartilhados ou gateways de produção. Não
são necessárias alterações no Windows, VPN, rotas, encaminhamento ou firewall do host.

## Compilação e testes sem privilégios

Usar a versão de Go do repositório, atualmente 1.27.3. A partir da raiz:

```bash
bash scripts/check-nft-poc.sh
go test -race -count=1 ./internal/configpoc
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
O coordenador e as sondas usam a conta confiável de laboratório UID/GID 1000,
sem privilégios. Nenhum serviço permanente é instalado. Se sudo não estiver
disponível, instalar por um console root local autorizado.

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

## Resultados observados e limites

Duas execuções limpas no Debian passaram em 15 cenários cada: 96 testes TCP/UDP
e 112 sondas negadas contínuas. O estado do host coincidiu antes e depois; os
três namespaces de teste foram removidos. Duração: 59,4–59,8 segundos; RSS máximo
de um filho: 13.076–13.420 KiB; journal: 189.813–189.816 bytes. Não é a memória
total do appliance nem um benchmark de capacidade. O rollback real do kernel
foi testado após falha simulada de outro componente; SIGKILL do coordenador e
expiração foram reais. A perda de confirmação do helper permanece simulada;
não foram validados sua morte, a do supervisor, falta de energia ou transportes
Web/CLI/API autenticados de produção. Confirmação incerta bloqueia novas alterações.
Não apagar o journal nem regras desconhecidas para forçar recuperação.
