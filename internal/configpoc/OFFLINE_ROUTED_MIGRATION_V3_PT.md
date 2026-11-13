# Atualização a frio de uma migração preparada

`PrepareOfflineMigratedRoutedStoreV3` atualiza apenas um armazenamento privado já preparado por `PrepareMigrationV2`. Preserva o objeto de migração, registros de origem, índices de recibos, associações explícitas de sujeitos, linhagem e gerações. Não substitui configuração existente, copia novamente o histórico, altera permissões ou invoca motores.

O perfil inicial limitado exige firewall schema 4 e serviços locais schema 3 com ação padrão deny, sem regras de forwarding, serviços ou interfaces. Os dois domínios devem ter Running, Startup e LastGood iguais, sem Candidate, transação pendente ou recuperação necessária. As regras existentes do firewall são preservadas. Outros estados precisam da recuperação ou administração autorizada; não são descartados nem têm a base ajustada automaticamente.

## Autoridade da origem e publicação

O instalador fornece roots retidos do destino e das duas origens, fingerprints explícitos, os três pools R2 existentes, orçamento e implementação confiável de `OfflineMigrationReadbackV3`. O core bloqueia firewall, serviços locais e destino nessa ordem. Relê as origens sob seus locks existentes, compara fingerprints com a migração copiada e mantém os locks durante verificação, publicação e fechamento do destino. Uma origem alterada é rejeitada antes do readback. O instalador também mantém parado o escritor administrativo anterior e retém o namespace do helper observado durante a chamada.

`VerifyMigratedSources` recebe cópias canônicas das revisões da migração validada. A implementação produtiva deve ler a política efetiva do helper anterior e verificar ausência dos recursos do domínio local declarado inativo. Listeners externos não são adotados nem apresentados como serviços ANDEIVA. Hash declarado, JSON do cliente, booleano ou motor simulado não constitui verificação. O callback não pode reentrar no destino enquanto seu lock estiver retido.

Uma publicação seleciona configuração schema 7, auditoria e testemunho da verificação da origem, R2, deadlines absolutos, perfil de leitor compartilhado e `configuration.routed-offline-migration.v1`. Esse testemunho **não** verifica o novo gateway. O coordenador exige autoridade routed, boot ID confiável, pools reais e deadlines absolutos; disponibilidade ainda exige Boot e readback físicos. G1 conserva as validações normais de testemunhos e migração, sem nova exceção para histórico não verificado. Leitores incompatíveis rejeitam o feature, que nenhuma publicação posterior pode remover.

## Interrupção e reversão

Antes da publicação do seletor, a migração anterior permanece selecionada; objetos imutáveis não selecionados podem permanecer. Interrupção com `selection.pending` conserva o bloqueio de recuperação existente e não permite repetição silenciosa. Após substituir o seletor, perder a resposta deixa uma seleção bem-sucedida incerta: reabrir apenas com o perfil compartilhado previsto e executar integridade e recuperação Boot física normais. Nunca remover o marcador ou reescrever histórico para downgrade. Preservar backups e evidências da tentativa; o operador pode preparar outro destino independente através da migração autorizada. Esta função não converte permissões nem implementa instalador de reversão automática.

## Testes e limites

Com Go 1.27.4:

```sh
go test -race ./internal/configpoc -run '^TestOfflineMigratedRoutedV3' -count=1 -timeout=2m
go vet ./internal/configpoc
go build ./...
```

O teste de compatibilidade exige `-args -reclaim-old-reader=/caminho/absoluto/prior-configpoc.test`. Compilar a fonte produtiva anterior adicionando apenas o adaptador independente `offline_routed_migration_prior_linux_test.go`. Primeiro comprova leitura do armazenamento privado original; depois exige rejeição pelo leitor **compartilhado** anterior. Sem o binário explícito esse caso é omitido e não fica qualificado.

Os testes usam journals e pools reais, replay, locks, concorrência, cópias de entrada, fechamento G1 completo, requisitos de runtime ausentes, recusa do verificador, cancelamento, falhas de publicação e reabertura. O verificador é um substituto unitário explícito: não qualifica o fornecedor nativo nem a transição do appliance. Não há alterações do host, aplicação de política, recuperação de espaço ou garantias de quota, falha elétrica ou desempenho produtivo. A publicação medida adicionou sete arquivos e 5.839 bytes lógicos em 22,3 ms no WSL; não representa RAM nem espaço físico alocado/livre e exclui a preparação completa da migração. A qualificação nativa de recursos permanece separada.
