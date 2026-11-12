# Observação de fluxos roteados somente para leitura

Tarefa `ROUTING-ALPHA-001/routed-flow-observation`. Módulo interno de laboratório;
revisão independente, transporte nativo, tráfego e recursos pendentes. Sem conexão
Web/CLI/API, persistência, pacotes ou ativação de mecanismos.

`Collect(context.Context)` solicita somente um dump IPv4 `CT_GET|DUMP` de
conntrack por NETLINK_NETFILTER no namespace **atual**. Não aceita nomes de
namespaces, setns, comandos ou shell; não altera rotas/NAT/sysctl. Não usa NEW,
DELETE ou GET_CTRZERO, não zera contadores, captura pacotes nem processa pacotes
em userspace. O launcher confiável controla namespace, privilégios, dependências,
limites da saída e duração do processo.

Exige `/sys/module/nf_conntrack_netlink` previamente existente. Não carrega o
componente nem troca de mecanismo. Ele está ausente no laboratório Debian atual;
o orquestrador prepara a dependência autorizada antes da qualificação. Kernels
built-in sem esse diretório são rejeitados conservadoramente.

Valida remetente kernel, grupos, porta local, sequência, multipart, tipos/tamanhos,
flags e duplicatas de atributos, tuplas duplicadas e término. Truncamento,
overrun, interrupção, ENOENT e erro nunca significam dump vazio válido. Atributos
desconhecidos têm estrutura/limites verificados, sem exportar dados. Padding
explícito só pode repetir nos grupos UAPI de contadores e timestamp. Headers/TLV
usam endian nativo; valores conntrack usam ordem de rede.

Limites: 64 KiB/datagrama, 4 MiB/dump, 8192 mensagens, 4096 fluxos, 256 atributos
por registro, seis níveis e dois segundos. Cancelamento é verificado ao menos a
cada 50 ms no polling. Qualquer erro devolve nenhum snapshot, mesmo após ler
registros. Um dump completo não é uma visão atômica durante tráfego vivo. O
launcher deve consumir/limitar stdout e impor seu próprio prazo de processo.

Somente TCP/UDP IPv4 é reportado; outros protocolos são contados como omitidos.
`original` e `reply` preservam tuplas do kernel. `forward_translated` inverte
reply; `reply_translated` inverte original. `source_changed` e
`destination_changed` comparam endpoints, sem alegar ausência de NAT identidade.
Tuplas traduzidas não inventam zonas; zona conntrack não é zona de segurança
ANDEIVA.

Estado TCP, status, mark, ID, zona e timeout são opcionais e vêm do kernel. UDP
não recebe estado TCP/estabelecido inventado. Novos valores TCP mantêm seu número
com nome `unknown`. Contadores ausentes são omitidos, diferentes de zero informado;
`width_bits` distingue 32/64 bits. Pacotes/bytes são strings decimais no JSON,
mantendo `uint64` interno e precisão além de 2^53; números JSON nesses contadores
são rejeitados. Não se inferem taxas, latência, aplicação,
usuário, permissão atual ou inspeção. Mark/conexão presente não comprova
autorização atual. Início/fim são leituras do relógio local, não timestamps
confiáveis de eventos.

Toda saída é evidência sensível de plataforma. Um adaptador futuro deve exigir
Platform Super Administrator no backend para API/CLI/export/jobs, com auditoria,
privacidade e retenção. Nenhuma superfície de admin comum ou bypass de
identificação/inspeção é conectado. Não habilita accounting ausente. JSON é emitido
uma vez após concluir o dump, sem armazenamento/log. Erros usam códigos estáveis
sem diagnósticos kernel ou endpoints.

Testes Linux/WSL com Go 1.27.4 e cache offline existente:

```bash
go test -race ./internal/routedflow ./cmd/andeiva-flow-lab
go test ./internal/routedflow -run '^$' -fuzz FuzzMultipart -fuzztime=10s -parallel=2
go test ./internal/routedflow -run '^$' -fuzz FuzzFlowAttributes -fuzztime=10s -parallel=2
go vet ./internal/routedflow ./cmd/andeiva-flow-lab
go test ./internal/routedflow -run '^$' -bench . -benchmem
go build -trimpath -o /tmp/andeiva-flow-lab ./cmd/andeiva-flow-lab
```

Testes usam datagramas sintéticos/transporte falso, sem operações privilegiadas;
cancelamento Linux para antes de abrir/usar socket. Cobrem SNAT, DNAT/twice NAT,
rota sem tradução, campos opcionais, endian, atributos inválidos, limites,
peer/sequência/multipart, truncamento, erros, duplicatas, cancelamento e
concorrência. Outras plataformas devolvem unsupported.

Após revisão, o orquestrador executa `/trusted/path/andeiva-flow-lab` sem argumentos
dentro do gateway isolado autorizado com dependência preparada. Deve comparar
endereços/portas com fluxos TCP/UDP conhecidos e peers vistos pelo servidor;
verificar accounting ativo/inativo, dump vazio, falhas e limites, preservando
invariantes externos de rotas IPv4/IPv6 e nftables do host.

O runner integrado oferece opt-in `--run-isolated-lab-with-flows`. Após revisão e
preparação autorizada, invoca seu próprio child fixo `--observe-current-flows`
dentro do gateway criado, após probes SNAT TCP/UDP e antes de mudanças de
regras/cleanup. Revalida bindings e leitura semântica atual; limita JSON a 1 MiB,
rejeitando campos duplicados/desconhecidos. Exige TCP 18080 e UDP 18081, origem
LAN 198.18.0.2, destino WAN 198.19.0.2, reply e inversos coerentes, origem traduzida
198.19.0.1 e `source_changed` verdadeiro. PAT pode mudar a porta de origem; métricas
ausentes não são inventadas. Imprime dados reais somente como `FLOW_OBSERVATION`
no stdout privado da unidade. O modo existente `--run-isolated-lab` não chama o
observer e funciona com componente ausente. Nenhuma carga de módulos, sysctl ou
rota de helper adicional; teste nativo integrado qualificado separadamente abaixo.

Rollback: parar/remover somente o binário staged; fechar o socket libera recursos.
Não cria objetos de rede ou estado persistente. Sem mudanças Docker/EKS, runtime
ou dependências. CPU/RSS e desempenho nativos seguem pendentes; sem alegações de
produto. [Projeto e referências](../README.md).

Evidência de fonte: unit/stub Windows, race/vet offline Linux/WSL, ambos fuzz de
dez segundos e cross-build Linux amd64/arm64 e Windows/Darwin unsupported PASS.
Gosec sem achados/supressões e Gitleaks sem segredos. Microbenchmark sintético
WSL: 6526 ns/op, 10416 B/op, 62 allocs; não mede CPU/RSS do dump real ou capacidade
do appliance. Nenhum teste de fonte abriu sockets conntrack reais.

A execução nativa em Debian 13 AMD64 passou em três namespaces isolados:
conntrack TCP/UDP real com tuplas original/reply/traduzidas coerentes com SNAT.
Contadores indisponíveis permaneceram ausentes. Passaram também ICMP related,
negação IPv6/reversa, revogação de conexão estabelecida, routing sem NAT e NAT sem
autorização de forwarding. Rotas IPv4/IPv6, nftables e forwarding do host ficaram
idênticos; namespaces removidos. O módulo local foi preparado expressamente fora
do collector e seu módulo folha foi removido ao terminar. Runner combinado:
3,853 s, CPU 0,395 s, pico cgroup 30.924.800 bytes, incluindo cache; não mede RSS
exclusivo do collector nem capacidade de produção. Nenhuma API administrativa ou
rota do appliance foi ativada.
