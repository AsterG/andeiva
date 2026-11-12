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
