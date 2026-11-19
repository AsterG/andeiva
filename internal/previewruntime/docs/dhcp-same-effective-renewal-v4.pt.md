# Renovação DHCP idêntica: perfil interno

Pré-requisito de desenvolvimento, desligado por padrão. Somente a montagem
confiável seleciona `RoutedDHCPSameEffectiveRenewalV4` antes de possuir
lease/gate/Work. Não ativa fábricas, configurações administrativas ou runtime.

Um epoch/sequência novo autenticado atualiza somente o mesmo proprietário,
interface e delta L3 efetivo canônico completo. Work conserva proveniência e
undo imutáveis. Encaminhamento e token anterior são fechados e verificados antes
da atualização. Abrir exige autoridade atual, política, integridade completa
e sequência nova. Um fence irreversível nunca é reiniciado.

Há uma interrupção breve por renovação. Testes nativos de TCP/UDP persistentes,
cada interrupção e mínimo/mediana/máximo, perdas observadas e recursos continuam
pendentes. O proprietário decide o máximo aceitável após medir; este componente
não afirma acesso sem perdas.

Após inspeção incompleta, o controlador solicita `refresh_only` com Work retido
antes de ler o proprietário. O helper valida o vínculo e fecha antes de verificar
readiness, owner ou hash que possam falhar. Esse caminho atualiza evidência
mantendo o fechamento; nunca abre, cria Work, retira configuração selecionada
ou inicia outra aquisição.

Retirar uma instância V4 renovada verifica baseline original e retirada
selecionada, libera L3 e conserva o mesmo gate fechado e seu watermark. Esse
runtime é terminal: rejeita Begin e mudança de perfil. A limpeza normal do helper
libera o gate fechado; fechamento incerto/fence conserva o erro. A identidade
nova pertence a PRs posteriores de contrato e comportamento.

Cancelar antes do primeiro frame não consome sequência nem inutiliza o canal
do owner. Falhas após começar a troca mantêm o fechamento estrito. Testes com
sessão/codec/controlador/scheduler e Gate reais e doubles controlados de
kernel/store. Sem daemon, worker periódico, dependência ou formato persistente
novo; qualificação nativa e recursos da integração continuam pendentes.
# Ensaio B2, revisão 2

O ensaio nativo B2 começa com uma concessão suportada de 71 segundos e fluxos
TCP/UDP existentes. O perfil 70 altera apenas o servidor do laboratório,
exige um RENEW70 natural real com encaminhamento fechado e termina antes do
prazo conservador autenticado do ensaio. O perfil 71 pausa brevemente apenas o
proprietário Go fixado por pidfd para provocar despacho tardio; depois exige
RENEW71 natural e nova abertura com os mesmos sockets. A pausa deve durar menos
de 1,7 segundos. Jitter, erros RPC, expiração ou limpeza incerta fazem todo o
ensaio falhar. BOUND após EXPIRE é reaquisição e não conta como renovação.
O wrapper versionado rejeita resultados antigos. São cenários exclusivos de
teste; a qualificação nativa e de recursos continua pendente.
