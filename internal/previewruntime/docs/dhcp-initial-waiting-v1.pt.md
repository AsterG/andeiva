# Espera da aquisição WAN inicial, versão 1

Nota de alteração: o controlador DHCP roteado experimental distingue a espera da aquisição inicial de uma falha que exige recuperação. A resposta de espera não contém concessão nem modifica a rede ou a configuração. Preserva uma qualificação de integridade já concluída; nunca cria prontidão nem autoriza tráfego.

O produtor lê atomicamente a fase de aquisição e a concessão. A espera exige uma aquisição confirmada e viva que nunca tenha concedido um endereço nem recebido uma revogação. O helper verifica se o trabalho selecionado foi liberado e se o encaminhamento está fechado antes de responder, sem efeitos sobre o gate ou o gestor de concessões. Versões desconhecidas, respostas malformadas, cancelamento, EOF, morte do proprietário, expiração e qualquer incerteza posterior aos efeitos mantêm o comportamento de falha. Nenhuma requisição pública pode fabricar esse estado. Pares antigos rejeitam a nova resposta em vez de interpretá-la como concessão.

Os testes usam pipes privados e o codec de controle reais, com substitutos explícitos para aquisição, kernel e armazenamento. Não comprovam integração DHCP nativa. A aquisição pelo controlador completo e as medições de recursos continuam pendentes. Nenhum processo, temporizador ou arquivo persistente é adicionado; begin acrescenta uma consulta nova ao proprietário dentro do prazo original.

Reprodução com Go 1.27.4 em Linux/WSL:

```sh
go test -race ./internal/dhcpclient ./internal/firewallipc ./internal/previewruntime -run 'TestInitialAcquisition|TestRoutedDHCP|TestRoutedIntegrity|TestConservativeLease|TestReconfigure' -count=1 -timeout=120s
go vet ./internal/dhcpclient ./internal/firewallipc ./internal/previewruntime
go test -c -o /tmp/andeiva-dhcp-waiting-v1.test ./internal/previewruntime
```

Reverter a alteração restaura o comportamento anterior de recuperação obrigatória; não restaura concessões nem amplia prazos. Nenhum procedimento de instalação ou ativação é introduzido.
