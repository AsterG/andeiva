# Inicialização do runtime agrupado V3

Esta biblioteca Linux conecta as factories V3 existentes em processos separados. É um componente experimental de integração, não um comando de implantação nem uma comprovação de prontidão para produção.

O supervisor root confiável chama `StartRoutedLaunchV3` com descritores fixados de namespaces isolados, diretório de sockets pertencente ao helper, armazenamento selecionado pertencente à API e três pools de reserva provisionados. Mantém esses recursos até `Close` retornar. O binário encaminha apenas `RoutedHelperRoleV3` e `RoutedAPIRoleV3` para `RunRoutedLaunchRoleV3` e encerra quando essa função retorna.

A API permanece no namespace do host sem capacidades. O helper entra no gateway isolado somente com `CAP_NET_ADMIN`. Seu grupo suplementar leitor difere dos grupos IPC e API. O executor usa `NewInOwnedNamespaceWithReader` com esse grupo confiável e ambos os descritores de namespace; o construtor anterior mantém suas restrições originais.

Os descritores herdados são fixos: 3 namespace gateway, 4 diretório de sockets, 5 armazenamento selecionado, 6 pool admission, 7 pool plan, 8 pool emergency, 9 pipe bootstrap, 10 pipe controle, 11 pipe eventos, 12 namespace host. Namespaces e diretórios são somente leitura; os pipes pertencem ao root. As posições são validadas antes da reabertura dos roots; aliases, tipos e modos incorretos são rejeitados. O bootstrap limitado vincula pai root, inicialização, namespaces, identidades e perfis.

A factory helper fornece a autoridade existente e uma sessão `NewRoutedCompatibilitySessionV2`. A factory API retorna `OperationsRuntimeOptionsV2` com o armazenamento herdado e seu perfil leitor. Não deve abrir um escritor antes de `OpenRoutedOperationsRuntimeV3`. Cada factory retorna seus recursos adicionais por `Cleanup`.

O helper cria sockets Unix após reduzir privilégios. Cada lado verifica UID, GID e PID reais do peer; nenhum socketpair criado pelo root é herdado. `ServeAPI` recebe o runtime aberto e o callback `ready`. Vincula seu listener TLS confiável após boot/resume e readback, chama `ready` exatamente uma vez e retorna quando o contexto é cancelado. Helper pronto não significa API pronta.

`RestartAPI` encerra e recolhe a API anterior, drena seus canais sem cancelar um efeito em andamento e depois libera o bootstrap da nova API. O handshake V3 avança a barreira do controlador antes de abrir o novo escritor. Helper e guardian permanecem vivos. Uma falha de reinicialização bloqueia novas tentativas naquele supervisor; a recuperação exige fechá-lo e seguir o procedimento aprovado do fixture.

`Close` encerra e recolhe os dois filhos diretos. A perda do helper também encerra a API. Os sinais por morte do pai mantêm a thread criadora viva até recolher cada filho. O chamador continua responsável pela limpeza do fixture e pela comprovação do encerramento dos descendentes antes de remover seus namespaces. A biblioteca não cria cgroups, provisiona interfaces, ativa serviços do host nem comprova limpeza completa dos descendentes.

Comandos na raiz do repositório:

```sh
go test -race -p 1 ./internal/previewruntime ./internal/networkexecutor -count=1
go vet ./internal/previewruntime ./internal/networkexecutor
go build ./...
```

Os testes focados cobrem argumentos fixos de privilégios, eventos limitados, rejeição de PID incorreto, drenagem/barreira e grupos leitores. Testes Unix no mesmo processo não comprovam o bootstrap privilegiado entre processos. Permanecem gates separados: factories nativas de três processos, negativas de descritores, recuperação após perda de processos, limpeza de descendentes e medições CPU/RAM. Este incremento não fornece implantação Docker/EKS.

A factory do helper deve usar `NewRoutedReadbackSessionV3` com a mesma autoridade
agrupada concreta. Compatibilidade não possui outro guardian. Seu bootstrap
indica somente ausência verificada da tabela legada; idle indica correspondência
física com revisão completa confiável. Nenhum comprova saúde do grupo,
confirmação ou permissão de gravação. O runtime e a leitura completa do Group
continuam obrigatórios antes de readiness. Leituras são serializadas com a
aplicação; políticas desconhecidas, falhas de captura e políticas deny
transitórias não selecionadas são rejeitadas. O epoch dos contadores muda antes
de cada aplicação tentada, incluindo erros e restaurações. Seu esgotamento
impede essa leitura sem reutilizar o contador nem impedir rollback.
