# Armazenamento v2: preparação e limites

Estes componentes internos preparam armazenamento, catálogo durável de operações e
migração a frio. Não estão conectados ao motor, API, CLI ou Web; não ativam Running.
Não alteram instalações v1 nem encerram AND-01/02. Credenciais e provas efêmeras
não pertencem ao catálogo.

Objetos imutáveis são selecionados atomicamente com cópia anterior. A consulta exata
usa três páginas limitadas e um objeto, sem mapa global em RAM. Identificadores são
vinculados a sujeito, namespace e lineage. Reutilizar slots exige retirada explícita,
retenção cumprida e ausência de operações fixadas. Repetições não executam efeitos
nem renovam a retenção.

A migração bloqueia os dois domínios originais e o destino, valida journals sem abrir
o serviço e preserva schemas, hashes, Startup, gerações e recibos. Rejeita estados
pendentes, origens clonadas e vínculos ambíguos. Publica uma seleção preparada única,
sequência 1; as fontes originais permanecem intactas.

Orçamentos de bytes/inodes são contábeis, não quotas ou reservas físicas. Ainda não
existe GC físico ou exportação/confirmação protegida. O histórico continua ocupando
disco e pode impedir novas admissões. Não há garantia contra perda de energia.

## Contabilidade física e margem de admissão

No Linux, v2 mede blocos alocados a arquivos com `fstat` (`st_blocks` em unidades
de 512 bytes), alocação do diretório e inodes, incluindo o diretório. Reconstrói os
contadores ao abrir sob bloqueio e os atualiza incrementalmente; não percorre o
catálogo a cada admissão. Conta ambos os seletores enquanto coexistem e não conta
duas vezes um objeto idêntico já verificado. Os orçamentos configurados limitam
tanto o uso lógico quanto a alocação física observada.

Antes da admissão consulta bytes/inodes disponíveis com `fstatfs` no descritor
validado do diretório. Preserva reservas alheias e acrescenta margem para
arredondamento e crescimento do diretório. Falta conhecida retorna limited sem
emitir operação, ocupar slot/reserva, publicar estado ou chamar motores. Somente
leitura ou métricas inválidas retornam unavailable. Estado verificado, consultas
retidas e repetições terminais continuam disponíveis; integridade ou publicação
incerta mantêm o bloqueio. Consultar espaço com sucesso não remove esse bloqueio.

É uma observação com margem estimada, **não uma reserva física**. Outros escritores,
quotas, metadados ou erros posteriores podem impedir publicação e recuperação.
A disponibilidade do filesystem ainda considera blocos de seletores removidos
que permaneçam abertos. Não adiciona fallocate, quotas, GC, remoção de histórico
protegido, mudanças de autenticação/auditoria ou ativação runtime. Continuidade com
volume cheio, testes físicos e encerramento AND-01/02 continuam pendentes.

Com dependências provisionadas previamente, sem rede:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -mod=readonly -buildvcs=false -race ./internal/configpoc -run '^TestV2Physical' -count=3
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -mod=readonly -buildvcs=false ./internal/configpoc -run '^$' -bench '^BenchmarkV2PhysicalPreflight$' -benchmem -count=3
```

Os testes cobrem alocação distinta do tamanho lógico, diretório, seletores
temporários, arquivos parciais/sparse, overflow, pressão antes dos efeitos,
reservas próprias, leituras verificadas e reabertura. Métricas injetadas não provam
ENOSPC/EDQUOT/EROFS reais. O preflight mediu 4,925–4,930 microssegundos,
812–828 bytes e 10 alocações por chamada em diretório temporário WSL Linux amd64;
não é dimensionamento do appliance nem teste de perda de energia.

Testes Linux com a versão Go indicada pelo repositório:

```sh
go test -race ./internal/configpoc -run '^TestV2' -count=1 -timeout 10m
ANDEIVA_CONFIG_V2_ENDURANCE=1 go test -race ./internal/configpoc -run '^TestV2DurableCatalogue5000Lifecycles$' -count=1 -v -timeout 35m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
```

O segundo comando mede 5000 ciclos do catálogo, não 5000 transações dos motores.
Testes de falha/processo não equivalem à perda de energia. Recuperar o preparado
exige preservar fontes e histórico: não apagar arquivos desconhecidos nem selecionar
revisões manualmente. Cutover, downgrade guard, readback global, paridade administrativa
e continuidade com disco cheio permanecem pendentes.


### Pressão v2 em cópias

Somente no laboratório Debian 13 autorizado, compilar `go test -c ./internal/configpoc`
e o inspector `andeiva-storage-lab`; preparar o perfil inativo conforme seu guia.
Como root, usar binários verificados e pertencentes a root:

```sh
bash packaging/preview/tests/storage-pressure.sh --authorized-debian-v2-volumes \
  "$TEST_BINARY" "$TEST_SHA256" --isolated-storage-only \
  "$INSPECTOR" "$INSPECTOR_SHA256" "$VOLUME_ID"
```

O modo admite somente bytes, inodes e arquivos removidos ainda abertos. Valida
originais/cópias e passa o escopo config e executável por descritores; worker
UID/GID 1000, sem grupos adicionais/capacidades e com NNP. Outros domínios ficam
root-only. ENOSPC real rejeita admissão sem Apply ou mudança de seleção;
lookup/replay e Save/reabertura posteriores passam. Motores são simulados.
Os três casos passaram em Debian: disponibilidade de bytes/inodes zero e blocos
retidos até fechar. Originais, sentinelas e limpeza verificados. Total 2,952 s /
CPU 2,236 s / pico cgroup 553.398.272 bytes incluindo cache. Não prova v2 somente
leitura, quotas/reserva física, recuperação de espaço de auditoria, continuidade
do dataplane real ou corte de energia; AND-01/02 continuam abertos. O readonly do
fixture anterior de volumes não pertence ao modo v2.

A pressão de bytes deixou disponibilidade zero; após liberar o arquivo de
preenchimento ficaram 112.132.096 bytes. A pressão de inodes atingiu zero inodes
livres com 111.476.736 bytes ainda disponíveis. O arquivo removido, mas aberto,
manteve disponibilidade zero até ser fechado; depois foram observados 111.075.328
bytes. São medidas do filesystem desta execução em cópias. O pico cgroup inclui
cache; não é RSS do processo, heap da aplicação ou dimensionamento de produção.

Consulte as [reservas de recuperação transacional](RECOVERY_RESERVES_V2_PT.md) para a integração interna de pools/coordenador e sua qualificação pendente.
