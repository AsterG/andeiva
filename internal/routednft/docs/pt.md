# Laboratório de firewall roteado e SNAT

Os testes de tráfego nativo no Debian 13 e a revisão independente passaram.
Sem integração Web/CLI/API, persistência ou pacotes.

A política tipada aceita somente regras IPv4 TCP/UDP ordenadas, com CIDR, portas,
interfaces e zonas do plano canônico. Protocolos não suportados, caminhos de
gerenciamento, referências inválidas, colisões de marcas e identificação/inspeção
obrigatórias são rejeitados. O experimento não implementa esses motores e não
autoriza automaticamente tráfego desconhecido. Masquerade LAN→WAN não concede
permissão de encaminhamento.

Cada regra exige `enabled` explícito. Uma regra inativa preserva configuração
validada e hash, mas não gera regras ou contadores do kernel. IDs existentes de
1–64 caracteres alfanuméricos/ponto/hífen/sublinhado, com início alfanumérico,
são preservados sem renomear. Rotas IPv4 e IPv6 do host são comparadas na saída.

A tabela exclusiva `inet andeiva_routed_alpha` não cria hooks INPUT ou OUTPUT e não altera políticas locais do host. FORWARD usa
prioridade 0 e política drop, incluindo IPv6; NAT postrouting usa prioridade 100.
Cada pacote verifica novamente a política atual e a tupla original do conntrack,
mesmo após SNAT. Respostas exigem estado estabelecido e marca de admissão da regra
atual; a marca não é identidade. RELATED permite somente erros ICMP
destination-unreachable, time-exceeded e parameter-problem associados à tupla,
marca, interfaces e regra atuais. Echo/redirects e erros sem vínculo não recebem
exceção. A matriz negativa completa e PMTU continuam pendentes.

O adaptador serializa Check→Apply→leitura semântica completa, com lote atômico.
Comentários/hash sozinhos não autenticam a política. Uma confirmação perdida
mantém somente os estados anterior/destino já autorizados. Contadores reiniciam
na substituição da tabela; não são inventário de conexões ou logs por fluxo.

Validação sem privilégios em Linux/WSL com Go 1.27.4 e cache offline:

```bash
go test -race ./internal/routednft ./cmd/andeiva-routing-lab
go test ./internal/routednft -run '^$' -fuzz FuzzReadback -fuzztime=10s -parallel=2
go vet ./internal/routednft ./cmd/andeiva-routing-lab
go test ./internal/routednft -run '^$' -bench . -benchmem
go build -trimpath -o /tmp/andeiva-routing-lab ./cmd/andeiva-routing-lab
/tmp/andeiva-routing-lab > /tmp/andeiva-routed-create.json
```

Após revisão independente, somente numa VM Debian 13 amd64 descartável e
autorizada, com snapshot de recuperação, iproute2/nftables e binário confiável:

```bash
sudo /tmp/andeiva-routing-lab --run-isolated-lab
```

O runner cria três namespaces aleatórios `andrt-...-{l,g,w}`, veths dentro deles e
forwarding somente no gateway isolado. Revalida inode do namespace e nome/MAC/índice
por `networkinventory.Discover` + `networkplan.Bind`. Não usa shell; executáveis,
saída e prazos são limitados. Compara rotas e nftables do host antes/depois por
observações somente de leitura.

Testa SNAT TCP/UDP pelo endereço observado no servidor, ICMP relacionado com
contador exato, IPv6 bloqueado com contador, conexão reversa não solicitada com
servidor/rota presentes, revogação de TCP já estabelecido, roteamento sem NAT e
NAT sem permissão de encaminhamento. Falha retorna código diferente de zero.
Não executar em equipamentos de clientes ou alterar redes do host Windows.

Rollback remove apenas namespaces criados pela invocação e com inode coincidente,
após parar seus filhos, em sucesso, erro, timeout, SIGINT e SIGTERM. SIGKILL/falha
física ou substituição de namespace podem deixar objetos: verificar propriedade
manualmente pelos nomes impressos; nunca remover apenas pelo prefixo. Rotas/NAT/SSH
do host não são modificados.

Testes reais: TCP/UDP com SNAT observado pelo servidor, ICMP relacionado, bloqueio IPv6 com contador, tráfego reverso não solicitado negado, conexão TCP existente revogada, roteamento sem NAT e NAT sem autorização de encaminhamento. Limpeza e invariantes externos de rotas IPv4/IPv6 e nftables aprovados. Processo de teste: 3,635 s decorridos, 0,312 s CPU e pico cgroup 30.273.536 bytes, incluindo filhos/cache; não é RSS do serviço nem medição de throughput.

Foram corrigidas incompatibilidades de contexto ICMP, conjuntos de tipos ICMP e seletores conntrack IPv4. A leitura preserva endereços, prefixos, portas, marcas e ações. Integração transacional, paridade administrativa, inventário de sessões traduzidas e testes sustentados/PMTU continuam pendentes. Não é um firewall de produção.
