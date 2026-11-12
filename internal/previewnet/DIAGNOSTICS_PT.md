# Diagnóstico privilegiado do ciclo de vida

O supervisor de namespaces, executado como root, registra eventos limitados `failure` e `cleanup_failure` no journal privilegiado existente. Eles contêm apenas categorias permitidas `phase`, `check` e `code`: nunca o erro original, saída de comandos, namespaces, rotas, caminhos ou credenciais. Os erros de comandos comuns e da API administrativa continuam genéricos.

A categoria da primeira falha é capturada em memória limitada antes da limpeza. Os diagnósticos são escritos somente após a limpeza: um escritor bloqueado não impede liberar recursos. A falha de limpeza é preservada separadamente e não substitui a original. Cada processo emite no máximo um evento de cada tipo, sem repetição ou histórico em memória. Não mudam as verificações do host, sentinel, listeners, prazos ou requisitos de recuperação. O estado residual continua exigindo a recuperação autorizada existente; estes eventos não autorizam exclusão ou reinício automático.

A fase indica onde a falha foi observada, sem provar sua causa. Um timeout na verificação de listeners não prova que eles pararam. Incidentes históricos sem esses registros não podem ser diagnosticados retrospectivamente apenas pelo erro genérico. O acesso ao journal é privilegiado; não incluir estes diagnósticos na UI comum, exportações ou pacotes de suporte gerais.

Controles positivos diretos e reversos mantêm a causa e o contexto quando já falham. Comandos com falha inesperada mantêm o erro do filho e o contexto do comando. Assim as categorias existentes `canceled`/`deadline` sobrevivem ao wrapping, sem campos novos. Saída 0 continua sucesso e 10 continua sem resposta; no-echo sem causa permanece genérico. Não mudam repetições, prazos, listeners, políticas, limpeza ou reinícios. Não determina a causa de uma queda anterior.

Testes sem privilégios no Linux com Go 1.27.4:

```sh
go test -race ./internal/nftfixture ./internal/previewnet ./cmd/andeiva-preview -count=3 -timeout=4m
go vet ./internal/nftfixture ./internal/previewnet ./cmd/andeiva-preview
go build ./cmd/... ./internal/...
```

Os testes usam verificações de saúde simuladas e o formato real de erros do comando. Não criam namespaces nem alteram o host. Verificam ordem, contexto original, causas preservadas, redação e eventos independentes limitados. A qualificação integral da falha do serviço permanece pendente.
Regressões adicionais usam peers TCP/UDP loopback reais que omitem ou corrompem o eco e subprocessos reais cancelados, expirados ou falhos. Verificam parada na primeira falha, semântica de saída intacta e os três campos redigidos existentes. A qualificação nativa desta propagação continua pendente; a medição anterior abaixo não qualifica esta mudança.
A qualificação nativa no Debian 13 do binário exato foi executada como UID 1000 com no-new-privileges e rede isolada: tempo de processo 0,028980 s, CPU 0,016426 s e pico de memória cgroup de 3.424.256 bytes. São testes puros/com fixture simulado dos diagnósticos: não demonstram falha real de namespaces, sua causa ou consumo do serviço completo.
