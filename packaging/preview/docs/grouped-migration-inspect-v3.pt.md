# Inspeção de migração offline

Com a API anterior e seu socket parados, executar `andeiva-preview grouped-inspect` como instalador root autorizado. Manter helper e gestor de namespaces vivos. O comando não os para, não altera contas nem prepara/ativa outro firewall. Lock ocupado rejeita a operação.

Um worker fixo APIUID sem capacidades usa o validador original e mantém o lock FW enquanto root escreve `/etc/andeiva-preview/grouped-migration-plan.json` usando O_EXCL e sincronização de arquivo/diretório. O rascunho privado vincula fingerprint exato e digest das contas a novos IDs duráveis e revisões de credenciais. Preserva identidades duráveis existentes. Não contém hashes de credenciais nem senhas. A saída mostra apenas hash do rascunho, fingerprint e identificadores.

A inspeção não cria vínculos históricos. Autorizar cada Source/Actor/ReceiptIndex a um subject específico na preparação posterior. Igualdade de nome ou credencial não autoriza. Reinspecionar preserva IDs e rejeita rascunhos inconsistentes; nunca substitui ou repara arquivos existentes. Um rascunho parcial é preservado para recuperação autorizada.

O filho aceita apenas pipes root herdados, FD de namespace fixado e pedido do pai root. Rejeita descritores adicionais inesperados; limita seu próprio processo a 256 FDs. Root fixa o thread criador até a saída. Testes cobrem privacidade, não substituição, FDs e argumentos; execução real exige fixture nativo explícito, não é comprovada pelos testes unitários.

O instalador cria o novo domínio inativo Local Services com `PrepareInactiveLocalSourceV3` somente após validar ausência real por autoridade confiável, Apply e leituras Current repetidas. O diretório separado, vazio e pertencente à API recebe exatamente um registro initialize com a data real. Domínios existentes ou parciais são preservados e rejeitados; falha de leitura após publicação mantém evidência e retorna erro. Não cria listeners, regras, identidades locais históricas ou autorização de ativação. Fixtures unitários modelam o motor de ausência e comprovam apenas persistência; o proxy privilegiado fornece a leitura implantada.
