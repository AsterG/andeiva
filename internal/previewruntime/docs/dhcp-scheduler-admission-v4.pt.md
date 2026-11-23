# Admissão do scheduler DHCP

Componente em desenvolvimento; validação nativa integrada pendente.

O scheduler DHCP selecionado ignora um ciclo quando a inspeção ou outra operação
ocupa o controlador. Cria um único contexto de tentativa de 30 segundos somente após
adquiri-lo e verificar cancelamento. Ignorar um ciclo não envia solicitações nem
fecha o canal. O cancelamento libera o controlador.

A reconciliação pública conserva o contexto original e a espera bloqueante.
Cada RPC mantém o limite de três segundos. Dois RPCs sequenciais de dois segundos
podem concluir a tentativa automática; um chamador manual com prazo de três
segundos ainda fecha o canal nessa sequência. O contexto não é renovado entre
fases. Cancelamento ou prazo menor do chamador continuam prevalecendo.
Concessões, confirmação, watchdog e recuperação não mudam. Não se implementam
orçamentos por fase, I/O cancelável do store nem recuperação geral de timeout.
O limite de 30 segundos é cooperativo: I/O ou locks bloqueantes podem atrasar o
retorno e o encerramento. Timeout não comprova rollback completo; referências
de recuperação são preservadas.

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
admissão, canal preservado ao ignorar ciclos, orçamentos de RPCs sequenciais,
prazos manuais ou menores e cancelamento/drenagem do scheduler. Negativos de
concessão expirada permanecem em `internal/networkexecutor`; estes testes não
qualificam publicação durável no limite completo de 30 segundos.
As duas regressões de contenção usam tempo real limitado porque esperar um mutex
não avança o relógio de `testing/synctest`; os limites usam tempo virtual.
