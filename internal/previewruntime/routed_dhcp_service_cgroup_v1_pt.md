# Escopo de processos do serviço DHCP, versão 1

Componente em desenvolvimento sob ADR-062. Não qualifica DHCP WAN, autoriza listeners, abre encaminhamento nem altera o contrato público da API, CLI ou web.

O supervisor confiável cria um cgroup filho novo por encarnação do serviço antes de iniciar o produtor. Seus descendentes herdam essa associação. Grupos existentes nunca são adotados. O bootstrap privado exige versão de serviço 1, identidade de dispositivo/inode do kernel e um nono descritor herdado (FD 11), aberto para leitura. Os perfis 3 e 4 mantêm sua semântica; implementações incompatíveis do bootstrap são recusadas. Antes de preparar montagens privadas, o receptor verifica pin, encarnação exata, associação e ausência de outros grupos filhos.

`RetainedServicePin` fornece um duplicado de leitura independente, pertencente ao chamador, com sua identidade. O supervisor deve obtê-lo antes do fechamento quando precisar preservar a origem anterior para observação. `Close` mantém o encerramento ordenado existente; depois solicita a terminação do grupo completo e verifica `populated=0` com um orçamento separado de três segundos antes de remover aquele diretório exato. Falhas de identidade ou drenagem preservam o erro e os recursos do grupo. Não há remoção recursiva nem adoção de processos arbitrários.

A drenagem de processos **não** demonstra ausência de sockets nem posse continuada. Um socket transferido pode sobreviver ao criador. O futuro observador deve manter o pin anterior e recusar sockets residuais até comprovar ausência física completa, sem reutilizar aquela origem. Um descritor de leitura delimita o inventário; não confina o produtor root confiável. Este componente não habilita exceções de listeners.

Sem aquisição DHCP, não introduz daemon, timer ou serviço. Aquisição nativa, capacidades, integração de desativação/readback, revisão de segurança e medições CPU/RAM continuam como gates separados. Não altera unidades instaladas, capacidades, rede do host, dependências ou contêineres/Helm. Requer Linux com cgroup v2, criação limitada ao escopo do supervisor, `CLONE_INTO_CGROUP` e `cgroup.kill`; não afirma compatibilidade com contêineres arbitrários.

## Validação

Os comandos reproduzíveis estão no [guia em inglês](routed_dhcp_service_cgroup_v1.md#validation). `TestNativeRoutedDHCPServiceCgroupV1` exige laboratório autorizado e unidade do supervisor sem uso prévio. Verifica localização real dos filhos, drenagem de vários processos, recusa de adoção e sobrevivência do pin após remover o diretório. Não opera na rede nem testa DHCP ou propriedade de sockets; testes normais o ignoram. Execução nativa e recursos devem ser registrados antes de qualquer afirmação de qualificação.

## Alteração de fonte

Adiciona escopo exclusivo do serviço de aquisição, pin privado obrigatório e API interna para retê-lo. O orquestrador mantém o registro compartilhado.
