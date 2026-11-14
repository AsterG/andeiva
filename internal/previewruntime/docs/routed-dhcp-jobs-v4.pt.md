# Integração do proprietário DHCP selecionado

O perfil explícito RoutedLaunchResourcesV3.DHCPJobs conecta runtime agrupado,
LAN bootstrap, produtor root adiado e executor de lease existentes. Exige
integridade. Static e NoNetwork não criam produtor nem timer reconciliador DHCP.
O supervisor mantém um socketpair privado; a API nunca o herda.

A primeira preparação desde NoNetwork escolhe executor estático ou LAN bootstrap,
com somente um escritor do namespace. Authority e DHCP compartilham a instância
LAN. Uma rede configurada mantém seu hash Desired exato. Stage, Prepare, Current
e api_ready não iniciam aquisição.

Somente após inspect/check completo, helper verifica bundle selecionado, política
idle real, leitura LAN e ausência independente de listeners. FD15 transmite
prepare/activate/stop tipados. Root lê Desired por um filho capless, fixa identidade
e pidfd do produtor e transfere exatamente três descritores reais. Activate
confirma o PID real de aquisição por canal privado.

A barreira live é o mutex existente do store em ServiceV2.InspectRuntimeV1,
mantido durante todo o RPC e revalidação final, mais ownership do controller
helper. Root não espera outro checkpoint flock. Compara a referência selecionada
completa antes/depois de Prepare/Activate; mudanças encerram o produtor antes do
ACK. Helper revalida antes de expor disponibilidade. Retirement usa o flock após
drenar processos. O resultado preflight não autoriza efeitos sozinho.

dhcp_selected é somente uma indicação privada para scheduling após inspeção
completa. R2 e o deadline BOOTTIME original autorizam cada efeito. Reconciliação
consulta a cada 500ms somente com DHCP selecionado. Inspeção pausa reconciliação
sem retirar um lease saudável. Falhas fecham token/forwarding e preservam evidência
R2 para retirada verificada. Sequência RPC não altera epoch do lease.

Rollback exige retirar WAN selecionado e parar o produtor antes de restaurar LAN.
LeaseGate.Dispose mantém o gate fechado para teardown do supervisor: não se
afirma ausência total de regras DHCP no scope reutilizado nem reattach arbitrário
após morte do produtor. Sem DHCP server ou alterações da rede host. Testes Debian
de aquisição, renovação/perda, inspeção, reinício API, rollback e drenagem, além
de medições de recursos e prontidão produtiva, continuam pendentes.
