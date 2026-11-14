# Admissão do scheduler DHCP

Componente em desenvolvimento; validação nativa integrada pendente.

O scheduler DHCP selecionado ignora um ciclo quando a inspeção ou outra operação
ocupa o controlador. Cria o contexto existente de três segundos somente após
adquiri-lo e verificar cancelamento. Ignorar um ciclo não envia solicitações nem
fecha o canal. O cancelamento libera o controlador.

A reconciliação pública conserva o contexto original e a espera bloqueante.
O limite agregado de três segundos e os limites de cada RPC permanecem:
dois RPCs de dois segundos ainda excedem o agregado e fecham o canal.
Concessões, confirmação, watchdog e recuperação não mudam. Não se implementam
orçamentos por fase, I/O cancelável do store nem recuperação geral de timeout.

Não são adicionados workers, timers, filas ou estado persistente. Evitar a espera
não comprova melhoria medida de CPU/RAM; aquisição e recursos nativos continuam
pendentes. Rollback por reversão do código, sem mudar a configuração selecionada.

Executar com Go 1.27.4 em Linux/WSL:

```sh
go test -race ./internal/previewruntime -run TestRoutedDHCPSchedulerV4 -count=1 -timeout=60s
go vet ./internal/previewruntime
go build ./internal/previewruntime
```

Os testes usam uma conexão de protocolo privado real e uma concessão simulada,
não um proprietário DHCP ou kernel nativo. Cobrem contenção, cancelamento na
admissão, canal preservado ao ignorar ciclos e limites individuais/agregados.
As duas regressões de contenção usam tempo real limitado porque esperar um mutex
não avança o relógio de `testing/synctest`; os limites usam tempo virtual.
