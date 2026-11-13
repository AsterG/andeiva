# Montagem do gateway gerenciado

O launcher nativo possui um namespace novo e duas interfaces filhas privadas.
Interfaces físicas são vinculadas por índice, nome, MAC e MTU. Uma identidade
local do nó preserva as MAC filhas entre RunIDs; não é credencial nem política
compartilhada. Namespaces existentes nunca são adotados.

Somente interfaces filhas identificadas podem ser ativadas ou removidas. O
launcher não configura endereços, rotas, NAT ou encaminhamento. IPv6 e forwarding
ficam fechados antes da criação. Efeitos L3 e sua verificação continuam no motor
transacional. A API permanece no namespace de administração.

Um registro root de cutover vincula os manifestos operacionais e de interfaces.
Não substitui G1: configuração selecionada e readback independente do helper
continuam obrigatórios. O namespace só é removido após recolher os filhos do
supervisor. Arquivos desconhecidos impedem limpeza ou reinício; não são apagados.
Instalar o pacote não cria a ativação nem habilita o serviço agrupado incompleto.

Testes cobrem vínculos, hashes, substituição de interfaces, cancelamento, perda
de confirmação e limpeza idempotente. Ciclo instalado, cutover frio, bootstrap
DHCP e Internet pelo cliente exigem validações independentes.

O comando opcional de preparação root `andeiva-preview grouped-retirement-slot` pré-aloca um recibo de retirada de tamanho fixo de4096bytes. A unidade agrupada pode escrever somente esse arquivo. Antes de emiti-lo, a parada normal deve observar apenas o PID supervisor no cgroup dedicado sem delegação e então liberar o namespace próprio exato. Descendentes, timeout, arquivos desconhecidos ou limpeza incerta impedem o recibo e preservam evidências de recuperação. Não garante recuperação após SIGKILL ou falta de energia. Os testes do arquivo e da drenagem real de processos são gates separados; o consumidor não deve ser ativado antes da aprovação de ambos.
