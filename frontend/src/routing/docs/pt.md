# Configuração roteada

A consola usa a capacidade autenticada de configuração v2. Instalar o frontend
não migra o armazenamento nem ativa motores. O editor atual admite duas
interfaces estáticas; recusa sobrescrever topologias maiores ou configuradas por
DHCP. NAT de origem exige uma regra Permitir independente.

As edições locais não afetam o tráfego. Preparar cria a candidata; Validar verifica
os dados. Aplicar exige confirmação em 30–120 segundos. Confirmar usa a operação
original e a revisão composta. Guardar conserva toda a Running para reiniciar;
restaurar Startup também exige confirmação.

A ordem é global e first-match: limpe a pesquisa antes de arrastar regras.
Com teclado: Espaço, setas, Enter e Escape. As regras desativadas continuam
configuradas e não avaliam tráfego.

Um resultado incerto bloqueia novas escritas. Consulte o ID conservado antes de
agir; executar novamente só é oferecido explicitamente para uma solicitação
aceita. Não há execução automática nem substituição por escritas v1.
Uma revisão selecionada não prova a aplicação: o estado efetivo exige observação
do kernel correspondente à geração e revisão.

Os testes do navegador usam respostas fictícias identificadas nos seus fixtures.
Cobrem EN/ES/PT, Light/Dark, teclado, acessibilidade e layout responsivo. Não
provam tráfego nem substituem a validação nativa. Os comandos de reprodução
estão no [README](../README.md).

A auditoria protegida exige administrador. Os filtros combinam-se sobre a página
carregada. A consulta tem limites de 1024 registos e 2 MiB e informa se ficar
incompleta. Os nomes vêm do registo atual; o ID do ator é durável. Não se inventa
a origem Web/CLI/API de registos históricos sem essa proveniência, nem se
apresentam alterações de configuração como eventos de tráfego.

Regras schema4 preservadas reutilizam tabela e editor sem inventar plano de rede.
Substituir ou descartar candidata exige revisão, ID anterior de Stage e geração
exatos. Stage nunca substitui candidata existente. O servidor verifica o dono
durável; controles não concedem permissão. Estas operações não alteram tráfego.
Bases históricas permanecem visíveis; Validate e Commit ficam bloqueados até uma
substituição explícita.
# Configuração DHCP LAN

A seção Rede permite editar escopos DHCP somente para LANs estáticas selecionadas.
As alterações entram no mesmo rascunho local e usam Preparar, Validar, Aplicar
com confirmação, Confirmar e Salvar. Desabilitar preserva todos os ajustes.
A versão 1 da política inalterada mantém seus bytes; adicionar DHCP usa a
versão 2 com `dhcp_server`. Não existe armazenamento nem API adicional.

São validados intervalos, exclusões, reservas, DNS/NTP, domínio e concessão/T1/T2,
mesmo com DHCP desabilitado. Alterar uma rede que invalide um escopo é rejeitado;
atualize ou remova esse escopo primeiro. O servidor mantém a autoridade final.
Habilitado na configuração não comprova serviço ativo nem concessões atribuídas.
Erros do servidor aparecem sem inventar telemetria nem ativar WAN.

Testes: `npm test`, `npm run build`,
`npx playwright test dhcp-settings.spec.ts routing.spec.ts`. Os testes de navegador
usam fixtures explícitos EN/ES/PT, Light/Dark e três tamanhos; não comprovam
DHCP nativo. Reverter o frontend não autoriza converter dados v2 para v1.

Para editar: Rede → Adicionar escopo, selecione a LAN estática, informe ID e
intervalo utilizável, preencha opções e temporizadores e mantenha o rascunho local.
Habilite pela caixa explícita e revise Preparar alterações. Validar e Aplicar
podem rejeitar uma configuração sem suporte de execução. Confirme o acesso após
aplicar antes de Salvar para reiniciar. Isso não comprova concessões DHCP.

Validação 2026-11-14: lint/typecheck, 71 testes unitários e build Docker aprovados;
72 testes de navegador DHCP/routing com fixtures, EN/ES/PT e Light/Dark aprovados.
Capturas revisadas em desktop e celular; nenhuma violação Axe no escopo verificado.
Não certifica acessibilidade completa nem execução DHCP nativa. Aumento gzip:
JavaScript 4,91 kB; CSS 0,07 kB. CPU/RAM sustentados pendentes; sem dependências,
sondagem periódica, processos novos ou alterações EKS/Helm.
