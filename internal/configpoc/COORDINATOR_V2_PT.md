# Coordenador interno de configuração v2

Preparação inativa sobre o mesmo armazenamento v2. Sem conexão ao appliance,
Web/CLI/API ou helpers; não migra instalações nem anuncia v2 automaticamente.
Preserva esquemas 4/3 e hashes em referências compostas de esquema 5. Contadores
por domínio independem do global. Candidate, Running, Startup e LastGood ficam
separados; Save é explícito.

Exige sujeito confiável autenticado e papel admin. Admissão sem efeitos; pending
e intent persistidos antes de Apply. Verifica todos os componentes antes de
selecionar estado, resultado e auditoria juntos. Incerteza bloqueia novas mutações.
Commit Confirmed mantém prazo e recuperação independentes da sessão/namespace,
com reserva própria. Rollback exige evidência de revisão verificada. Mutações de
serviços locais são negadas até concluir testes de listeners e confirmação.

Comandos reproduzíveis na [guia inglesa](COORDINATOR_V2.md). O teste opcional
executa 5.000 ciclos, 30.000 operações e 20.000 Apply simulados; informa RSS/heap/
CPU e uso lógico/alocado de disco/inodes. Requer vários GiB e centenas de milhares
de inodes em diretório isolado. Não comprova tráfego nftables, cortes elétricos ou
continuidade do appliance. Integração de motores, identidade durável, paridade
Web/CLI/API, ativação voluntária, serviços locais e capacidade física continuam
pendentes. Nenhuma auditoria protegida é excluída; não há retenção infinita.
