# Configuração DHCP LAN preparada

A política routed versão 2 acrescenta o objeto obrigatório `dhcp_server`, com o esquema 1 existente do servidor DHCPv4. A versão 1 exige a ausência do campo e mantém bytes canônicos e hashes. A configuração externa permanece no esquema 6, o composite no 7 e network no 1. Há um único armazenamento de configuração e coordenador; DHCP integra a revisão routed/firewall existente.

A canonicalização copia todos os dados aninhados. Ordena escopos, pools, exclusões e reservas deterministicamente; preserva a ordem de DNS e NTP. Os bindings são derivados das LANs estáticas do network selecionado, não de inventário runtime fornecido pelo cliente. Isso valida consistência desejada, não propriedade física, disponibilidade de interfaces ou execução do servidor. Configurações desabilitadas continuam validadas e preservadas.

O feature persistente `configuration.routed-dhcp-server.v1` acompanha a primeira operação selecionada que contém essa política. A publicação de Candidate/configuração também assegura o feature. Descartar o Candidate não o remove. Leitores anteriores devem rejeitar antes da reconciliação; rollback não permite removê-lo para executar um binário antigo. Não há migração implícita de armazenamentos anteriores.

A autoridade routed confiável deve implementar `RoutedDHCPServerSupportV1` e declarar suporte explícito. Nenhuma autoridade existente habilita esse suporte. Sem ele, a admissão é rejeitada antes da manutenção de reservas, claims ou publicação; abrir armazenamento marcado é rejeitado antes da recuperação e dos efeitos dos motores. A capacidade não é prova física. Só pode ser declarada quando ativação, leitura efetiva, compensação e encerramento completo incluírem o servidor; verificar nft isoladamente não basta.

Stage, Commit confirmado, Save e rollback reutilizam a transação conjunta. Rollback de configuração não pode restaurar dados antigos nem descartar concessões emitidas. Não são adicionados banco de concessões, launcher Kea, unidade, endpoint, UI, ativação runtime ou implantação. O futuro adapter deve comprovar persistência, pressão de armazenamento, serviço real, desativação sem recursos e recuperação antes de habilitar-se.

Os limites permanecem: entrada DHCP de 64 KiB e envelope atual de operação de 8 KiB. Uma configuração DHCP válida isoladamente pode exceder o transporte preparado: será rejeitada sem truncamento. Nenhuma quota aumenta. A previsão de metadados reserva o tamanho do feature. Medições de recursos runtime continuam pendentes.

```sh
go test -race ./internal/dhcpserver ./internal/routedmodel ./internal/configpoc -run 'TestCanonical|TestDHCPServer|TestReserveEnvelope'
go vet ./internal/dhcpserver ./internal/routedmodel ./internal/configpoc
go build ./...
go test ./internal/dhcpserver -run '^$' -bench '^BenchmarkCanonical$' -benchmem
```

Usar o toolchain Go do projeto. `TestDHCPServerOldReaderBarrier` também exige `-reclaim-old-reader=/caminho/absoluto/prior-configpoc.test`, compilado da fonte anterior com o adapter existente `TestReclaimPriorReader`. Sem esse binário, o caso é ignorado; isso não representa PASS de compatibilidade. Os testes usam armazenamentos temporários reais e motores simulados, não um servidor DHCP nativo.
