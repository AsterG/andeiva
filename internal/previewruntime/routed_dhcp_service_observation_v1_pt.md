# Observação dos recursos de aquisição DHCP, versão 1

Componente em desenvolvimento sob ADR-062. Não autoriza encaminhamento, substitui recuperação de concessão/R2, demonstra posse atual de sockets ou qualifica um appliance instalado.

A resposta privada root/helper `prepare` exige versão de cgroup 1, dispositivo/inode do kernel e quatro descritores SCM_RIGHTS: pipes de pedido/resposta, pidfd do produtor e pin de leitura do cgroup. `activate` e `stop` recusam descritores e metadados de preparação. Pares antigos e dados desconhecidos, ausentes ou extras são recusados. O contrato público API/CLI/web não muda.

O helper verifica binding autenticado, cgroupfs, acesso, proprietário, identidade, caminho exato da encarnação, pidfd/início e associação do produtor. Mantém duplicados independentes. A visão é instalada antes da ativação; standby exige inventários vazios e não consome `Current` antes do ACK root. A ativação tipada mantém o mutex do listener até o ACK; depois, a observação consulta diretamente o leitor autenticado, sem retornar ao mutex do runtime ou da autoridade.

São capturadas as quatro tabelas TCP/UDP e inventários limitados UDP/AF_PACKET no namespace gateway retido. Duas capturas sequenciais verificam identidade, concessão e fase antes/depois; não há afirmação de atomicidade do kernel. Cada inventário deve cumprir o perfil completo. Sockets podem aparecer/desaparecer, mas um inode retido não pode mudar silenciosamente cookie ou atributos. Não existe autoridade por cache ou extensão de prazos.

Somente um UDP IPv4 é admitido: UID 0, porta 68, endereço vigente exato, inode correlacionado e cgroup de criação exato. Duas leituras físicas devem localizar esse endereço somente na WAN selecionada por nome/MAC. Ifindex 0 não demonstra bind-to-device. Wildcard, origem externa, endereço diferente, UDP extra e listeners TCP/IPv6 são recusados.

O perfil suportado do motor mantido exige RAW/ETH_P_ALL, UID 0, flags 3 e ifindex WAN exato não nulo. Fonte e medição isolada sustentam espera inicial com zero a dois packet sockets e nenhum UDP; com concessão vigente, um a dois packet sockets e zero ou um UDP válido. Dois é o limite do perfil suportado, não um máximo universal do kernel. Outro tipo/protocolo/flags, LAN, ifindex 0 ou excesso são recusados. `packet_diag` não comprova cgroup, titular atual nem filtros BPF instalados/bloqueados. O motor privilegiado mantido e a exclusividade do papel RAW pertencem ao TCB; não se afirma contenção de um raw socket comprometido por regras IP. Consulte a [fonte mantida](https://raw.githubusercontent.com/NetworkConfiguration/dhcpcd/v10.1.0/src/if-linux.c).

A retirada primeiro revoga a visão. O ACK de stop comprova somente drenagem de processos. Os pins são liberados após observar saída no pidfd e dois inventários TCP/UDP/packet completamente vazios. Resíduos ou incerteza preservam os pins e impedem retirada limpa. Sem serviço DHCP, exige ausência estrita. Não adota grupos, sockets ou processos.

Não adiciona workers persistentes, timers, escritor DB, dependências, serviços ou capacidades. Perfil da unidade, redução real de UID, aquisição/renovação/retirada integrada, revisão independente e CPU/RAM permanecem sujeitos a gates separados. Não altera contêineres/Helm; exige o conjunto Linux existente. Comandos no [guia em inglês](routed_dhcp_service_observation_v1.md#validation). Os testes distinguem modelos de inventário/I/O e SCM_RIGHTS real sem privilégios da validação nativa do adaptador.

## Alteração de fonte

Observação estrita dos recursos de aquisição e retirada condicionada à ausência física; extensão somente do bundle privado prepare. O orquestrador mantém os registros compartilhados.
