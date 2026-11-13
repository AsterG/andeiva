# Inspeção de integridade do armazenamento selecionado

`CaptureReferenceV1` lê e revalida o cabeçalho selecionado limitado, inclusive durante uma recuperação existente. A tupla serve para correlação; não autoriza ações nem declara disponibilidade. `InspectionReference` também rejeita configurações com Intent, Pending ou RecoveryRequired. Nenhum desses métodos percorre todo o histórico.

`InspectQuiescentV1` aceita somente o leitor padrão de histórico completo. Antes de G1, verifica a tupla exata e a ausência de trabalho com efeitos pendentes. Executa os validadores existentes do grafo completo e das reservas; depois revalida seletor, registros retidos, perfil do diretório e as três capturas dos pools. O leitor limitado à autorização por ação não pode declarar uma inspeção completa.

O chamador deve manter a barreira de escrita/publicação da API e verificar separadamente se o guardian está inativo ou em bootstrap. O leitor não adquire o bloqueio do escritor nem impõe esse protocolo externo. Operações aceitas e reservas potenciais de fechamento são permitidas quando a configuração está em repouso; seus claims são validados sem executar, expirar, liberar ou reiniciar prazos. Isso evita exigir novas tentativas do cliente antes da inspeção inicial.

Somente `complete` sem erro qualifica a tupla inspecionada. Cancelamento, correlação obsoleta e dados indisponíveis não a qualificam. Uma leitura limitada bem-sucedida seguida de hash ou decodificação canônica inválidos mantém evidência de corrupção apenas nessa chamada; resulta em `fenced` somente após revalidar seletor sem mudanças, reservas e perfil. Erros desconhecidos, limites esgotados, registros ausentes e perfis inacessíveis permanecem indisponíveis. O leitor não persiste nem remove o bloqueio do helper.

Os limites existentes de grafo, bytes, descritores e E/S são preservados. A classificação de erros reutiliza o mesmo orçamento, sem outra varredura. Nenhum cache sobrevive à chamada. O cancelamento é cooperativo: não garante interromper uma operação de filesystem bloqueada. Não há publicação, limpeza, chamadas a motores ou autorização para coleta de objetos.

Os testes Linux usam armazenamento e pools temporários reais com motores simulados. Cobrem operações aceitas, reserva potencial, Pending/Intent reais, política completa, tuplas obsoletas, cancelamento, histórico corrompido, perfis, limites e arquivos inalterados. Não qualificam implantação, isolamento nativo entre usuários, metas de desempenho ou o agendador completo.

Com Go 1.27.4 e dependências offline previamente disponíveis:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc -run '^TestIntegrityReaderV1' -count=1 -timeout=3m
GOPROXY=off GOSUMDB=off go vet ./internal/configpoc
```
