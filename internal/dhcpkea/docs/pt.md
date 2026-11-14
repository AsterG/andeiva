# Compilador DHCP para Kea 2.6.3

Somente compilação determinística; não cria processos, listeners, arquivos de
concessões, unidades, API, armazenamento ou mudanças de rede. Habilitação exige
qualificação nativa.

`Compile(dhcpserver.Config, []Binding)` reutiliza validação do esquema 1. Assembly
fornece exatamente um binding por escopo retido: LAN estática selecionada, nome
kernel e `SubnetID` estável entre 1 e 4294967294. Bindings excluídos de JSON;
validação não comprova propriedade física. WAN, IPv6, nomes/IDs duplicados,
bindings ausentes/extras, wildcards/seletores e configurações inválidas são
recusados com `ANDEIVA_DHCP_KEA_INVALID`.

Assembly **deve preservar a associação escopo/SubnetID entre revisões e reinícios**.
Não derivar da posição, truncar hashes, adotar identidade antiga sem prova ou
criar outra base de configuração. Não há alocador/histórico nem garantia de
continuidade de concessões neste pacote.

Disabled valida escopos retidos e retorna `Enabled=false`, `JSON=nil`, digest
vazio. Caller ainda deve drenar/observar recursos antes de declarar desabilitado.
Enabled fixa RAW apenas LAN, require-all, zero tentativas adicionais, lease/T1/T2,
gateway, DNS/NTP ordenados e domínio opcional. Ordena/divide pools removendo
exclusões e reservas; pool esvaziado permanece vazio. Reservas MAC fora dos pools
dinâmicos não autenticam dispositivos. Matching DHCP client-ID normal permanece;
reservas administrativas por client-ID não são suportadas.

Cada sub-rede exige classe fixa correspondente à interface de entrada, inclusive na seleção por endereço em renovações. Classe DROP fixa para relay giaddr/option82. Sem DDNS, hooks, control socket,
credenciais DB, opções arbitrárias, caminhos/executáveis do caller ou DHCP4o6.
Não gera nftables nem permissão forwarding/NAT. Isolamento RAW, identificação,
política local e tráfego desconhecido continuam requisitos do runtime.

Solicita memfile persistente em `/var/lib/andeiva/dhcp-server/leases4.csv`, limpeza
horária. **Nunca restaurar esse estado de uma revisão de configuração**. Ownership,
LFC confinado, quotas, reinício, migração, disco cheio e perda de energia exigem
testes reais. `max-row-errors=1` ainda omite uma linha corrupta no Kea 2.6.3 antes
de falhar na segunda; zero seria ilimitado. `lease-checks=warn` evita correção/remoção
automática, mas não prova validade. Runtime deve recusar estado histórico corrupto
ou não comprovado antes de servir. `-t` não resolve esse gate; nenhum parser CSV novo.

Limites: 32 escopos, 32 pools declarados/escopo, 256 exclusões e 256 reservas/escopo,
65.536 endereços declarados totais, 64 KiB entrada e 1 MiB saída. Intervalos sem
enumerar redes. Uma thread, fila desabilitada, uma amostra estatística e stdout/WARN
não qualificam desempenho, auditoria ou retenção de logs. Digest identifica bytes,
não revisão selecionada/autoridade. Entradas não mudam; reordenação de conjuntos
preserva saída, prioridade DNS/NTP permanece deliberadamente.

```sh
go test -race ./internal/dhcpkea
go vet ./internal/dhcpkea
go test -run='^$' -bench=Compile -benchmem ./internal/dhcpkea
GOOS=windows GOARCH=amd64 go build ./internal/dhcpkea
```

Fixture sintética `../testdata/kea-2.6.3.json` comparada byte a byte. Root pode
validar com Kea 2.6.3 verificado e `-t` em laboratório isolado; sem prova de execução
ou persistência. Medição Linux/WSL: race 1,091 s; pequeno 9.991 ns/op / 4.593 B;
denso dois escopos 768.860 ns/op / 450.129 B. Três escopos densos:49.321 B → 100.897 B;
quatro excedem entrada e são recusados. Não é benchmark appliance nem runtime
Docker/EKS novo. Revisão independente e testes nativos pendentes.

São omitidos `cache-threshold` e `cache-max-age`: Kea 2.6.3 exige configuração
explícita para ativar o cache e rejeita um limite zero configurado. A regressão
verifica sua ausência. Esse padrão não comprova durabilidade dos leases;
falta repetir a análise nativa após as rejeições iniciais. Fonte:
`BaseNetworkParser::parseCacheParams` e `AllocEngine::setLeaseReusable`.

Referências: [DHCPv4](https://kea.readthedocs.io/en/kea-2.6.3/arm/dhcp4-srv.html),
[classificação](https://kea.readthedocs.io/en/kea-2.6.3/arm/classify.html) e fonte
2.6.3 `lease_file_loader.h`/parser DHCPv4.
