# Carregador e supervisor da implantação agrupada

Este conjunto é experimental e a instalação do pacote não o ativa. As unidades agrupadas não têm destino de instalação. Não habilitá-las antes de concluir migração offline, provisionamento autenticado de namespaces e testes de recuperação.

O supervisor root lê apenas `/etc/andeiva-preview/grouped.json`. O manifesto versionado fixa o digest das contas, quatro identidades de diretórios compartilhados, três perfis de reserva e orçamentos explícitos de leitura/escrita. Não contém políticas nem autoriza sua aplicação. O helper verifica independentemente a configuração selecionada e sua integridade completa antes de permitir mutações ordinárias.

Os recursos em `/var/lib/andeiva-preview/grouped` e `/run/andeiva-preview/grouped` devem existir com proprietários e permissões exatos. O carregador não cria namespaces, contas, políticas ou diretórios. Os descritores devem vir do gestor confiável e corresponder à identidade atual de inicialização/execução. Namespaces e journal anteriores permanecem separados. A migração offline deve preservar políticas e histórico; uma configuração de teste vazia não constitui atualização.

O listener administrativo é herdado do socket systemd dedicado. Endereço, interface e namespace host são verificados antes de iniciar os filhos; não são aceitos curingas ou caminhos escolhidos pelo chamador. O socket de saúde é separado do diretório da API anterior. Disponibilidade do listener não significa integridade ou qualificação do plano de dados.

A API tem orçamento constante de três reinícios por minuto, com espera de três segundos. Uma falha de reinício ou esgotamento do orçamento mantém administração degradada, supervisor e helper vivos. O guardian preserva seu prazo original. Não há reinício automático do helper, limpeza da barreira de integridade ou remoção insegura de socket residual. Pode ser necessária recuperação operacional. A parada explícita fecha os filhos; falhas do helper são informadas separadamente.

Os testes cobrem manifestos estritos, tipo/identidade do descritor e esgotamento modelado de reinícios. Não qualificam sandbox systemd, instalação, tráfego real ou implantação permanente. As unidades permanecem desabilitadas até essas verificações passarem.

O `namespace_profile` explícito é `host-gateway-v2`: metadata schema 2 exige apenas namespaces host e gateway reais. Este carregador não cria nem aceita namespaces source/sink de teste.

Uma implantação schema 2 também exige `local_origin` versionado: kind `new-inactive-v1`, data real de auditoria da inicialização, fingerprint completo da origem local importada e sua revisão. Identifica um domínio inativo recém-criado, não um journal anterior ou diretório de marca de inicialização. O launcher copia o valor sem alias do chamador. Antes de construir um motor ou aplicar Startup, o helper compara todos os campos com a imagem de migração realmente selecionada e verificada pelo G1 completo. Origem ausente ou incoerente rejeita a inicialização; não substitui evidência histórica por diretório, hash do chamador ou leitura do namespace novo.
