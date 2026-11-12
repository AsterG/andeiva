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
