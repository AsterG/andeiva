# Aquisição DHCP sem concessão

O serviço pode continuar vivo após expiração ou revogação. Sua observação atômica
distingue esse estado da espera inicial, de uma concessão válida e de falhas do
processo ou canal. A observação sem concessão contém apenas uma época monotônica
de revogação e a identidade autenticada de aquisição. Não restaura uma concessão,
reinicia o motor, amplia prazos nem autoriza encaminhamento.

Após retirar e persistir o trabalho selecionado anterior, `dhcp_begin` pode
retornar um resultado versionado sem efeitos. Primeiro verifica LAN original/WAN
vazia, encaminhamento desativado, gate fechado ou ausente, trabalho liberado e
runtime pronto. Outra observação atômica confirma a aquisição; se BOUND já chegou,
segue com essa concessão pelo caminho normal. Somente esse resultado anterior aos
efeitos preserva a autorização existente do cliente; nunca a cria. Erros genéricos
e cancelamento mantêm seus bloqueios.

Sem concessão, a visão de recursos permite apenas o perfil limitado de sockets
raw WAN do serviço, sem listeners TCP/UDP. Concessão, R2, época e prazo continuam
controlando L3 e encaminhamento. Morte do proprietário ou falha de protocolo exige
recuperação supervisionada; outro PID ou cgroup não é adotado. O supervisor e a
contenção existentes permanecem inalterados.

Os testes cobrem EXPIRE/BOUND atômicos, pipes privados reais, codec/cliente, replay
de épocas revogadas, cancelamento, mensagens mistas e listeners proibidos.
Executar `go test -race ./internal/dhcpclient ./internal/firewallipc ./internal/previewruntime -run 'Test(AcquisitionNoLease|RoutedDHCP(NoLease|WaitingV1|InitialWaiting))'`.
Renovação/reaquisição nativa, privilégios da unidade instalada e medições de
recursos continuam pendentes. A mudança de código não qualifica o appliance.
