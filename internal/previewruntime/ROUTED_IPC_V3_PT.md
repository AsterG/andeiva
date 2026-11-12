# Transporte do helper com seleção durável

O protocolo3 agrupado não retorna a escritores independentes antigos. Usa somente
canal Unix autenticado pelo supervisor; wrappers herdados verificam UID, GID e PID
do kernel. O cliente sem privilégios envia preparação canônica ou referência.
O helper reconstrói seleção completa, G1, bancos, scope e propósito. Hash ou
boolean serializado não concede autoridade. Geração do Work e geração global são
diferentes. Preparação somente leitura compara a expectativa com Startup,
testemunho salvo e baseline independentes; não recebe caminhos, comandos, TTL ou
identidades do solicitante.

O controlador mantém exclusão até completar chamada e resposta, mesmo após perder
o cliente. Novo escritor deve concluir handshake antes de abrir o armazenamento.
Resposta perdida encerra canal sem repetição ou renovação de prazo; guardian
continua independente. Limite: três artefatos de256KiB+4096bytes, preservando v1/v2.

Testes unitários/race cobrem frames inválidos, scope/sequência, planos não
verificados, exclusão e credenciais Unix reais. Usam motores fixture; não provam
nftables nativo, acesso ao armazenamento entre processos ou ativação permanente.
Integração, implantação nativa e recursos do helper montado continuam pendentes.

```sh
go test -race ./internal/firewallipc ./internal/previewruntime -run 'TestRouted(Codec|Client|Reply|Session|Inherited)V3' -count=1
go vet ./internal/firewallipc ./internal/previewruntime
```
