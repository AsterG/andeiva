# Proprietário de aquisição DHCP roteada v3

Estado: implementação isolada. Integração do runtime agrupado, revisão
independente, testes nativos DHCP/privsep e medições de recursos pendentes.
Contrato interno de desenvolvimento, não manual operacional do appliance.

Reutiliza `dhcpclient.StartIsolated` e o perfil fixo do dhcpcd mantido.
Não configura endereços, rotas, DNS, listeners, Forward ou NAT. O lease fornece
evidência ao runtime selecionado; não autoriza novas políticas.

Somente o supervisor root pode chamar `StartRoutedDHCPOwnerV3`, que inicia a
aquisição imediatamente. Antes, deve verificar integridade do helper, revisão
DHCP canônica selecionada, bootstrap/readback LAN e EmptyListeners independente.
Não enfraquecer esses gates. WAN estática não deve criar processo; planos sem
DHCP são rejeitados. A integração dessa ordem continua pendente.

O papel separado exige root pelos requisitos existentes de namespaces,
montagens privadas e privsep do dhcpcd. NET_RAW isolada não está validada.
Revisar capacidades e filtros da unidade root antes da ativação. API permanece
sem privilégios e helper mantém NET_ADMIN. Unidades e implantação não mudam.

O supervisor fornece descritores retidos e estado canônico, nunca autoridade
vinda de API/CLI/helper. Executa apenas seu binário confiável com o papel
`RoutedDHCPOwnerRoleV3`, usando argumentos fixos de `/usr/bin/nsenter`.
O dispatcher deverá chamar `RunRoutedDHCPOwnerRoleV3`.

FDs do papel separado: 3 namespace gateway, 4 namespace de rede host, 5 namespace
de montagens host, 6 bootstrap, 7 eventos, 8 solicitação Current, 9 resposta
Current, 10 Stop exclusivo root. FD13/FD14 do helper não mudam. O integrador
deve atribuir novos FDs ao helper e fechar cópias paternas depois da herança.
`TakeReaderFiles` permite uma única transferência. Nunca entregar binding ou
descritores à API; o conteúdo do binding sozinho não autentica.

São verificados pai root/PID/start, namespaces, cgroup, pipes privados e vínculo
nome/MAC/índice da interface. Root fixa com pidfds o papel e o processo dhcpcd
real, repetindo identidade e vida antes de transferir autoridade. Current
serializa novas solicitações, com frames de até 8 KiB e dois segundos incluindo
espera do lock. Sequência RPC e sequência/epoch do lease são distintas:
consultas repetidas retornam fact idêntico e prazo BOOTTIME original.

JSON malformado/duplicado, replay, incarnation incorreta, EOF, cancelamento,
morte ou expiração rejeitam acesso; nunca há fallback ao lease armazenado.
Indisponibilidade revoga o epoch; somente outro epoch confirmado o substitui.
TIMEOUT armazenado não concede autoridade. Consultar não estende prazo.
Current não aceita comandos, caminhos, Stop ou renovação forçada; dhcpcd mantém
renovação/rebind. Stop usa apenas o canal root e aguarda filho e descendentes
adotados antes de confirmar. Controle inválido ou EOF interrompe sem confirmação
de sucesso. Morte abrupta ou falha de início exige drenagem de todo o cgroup
dedicado antes de retirar o scope, usando o gate existente.

Montagens mudam somente dentro do namespace privado verificado: propagação
privada, `/run` e `/var/lib` tmpfs de 4 MiB cada e três diretórios de 1 MiB,
128 inodes por montagem, nosuid/nodev/noexec. São capacidades máximas, não RSS
medido. Sem sockets públicos ou timers coletores. Saída dos processos descartada;
erros de protocolo usam códigos genéricos estáveis.

Testes reproduzíveis com Go 1.27.4, `GOTOOLCHAIN=local`:

```sh
go test -race ./internal/previewruntime -run TestRoutedDHCPOwnerV3 -count=1 -timeout=2m
go test -race ./internal/previewruntime ./internal/dhcpclient -count=1 -timeout=3m
go vet ./internal/previewruntime ./internal/dhcpclient
go build ./internal/previewruntime ./internal/dhcpclient
GOOS=windows GOARCH=amd64 go test -c ./internal/previewruntime -o /tmp/andeiva-owner-windows.test.exe
```

Testes usam pipes, evidência fictícia e processo sem privilégios para pidfds.
Não executam DHCP, montagens ou mudanças de rede. Não comprovam funcionamento
nativo, Docker/EKS, ACK real, renovação, reinício ou limpeza do cgroup.
Outras plataformas rejeitam início/reader. Rollback: remover estes arquivos
novos ainda não integrados; configuração instalada e estado compartilhado intactos.
