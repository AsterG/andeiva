# Observação conjunta nova em cada chamada

O adaptador experimental obtém a revisão atual e a referência do estado
controlado de uma observação semântica completa sob o mesmo lock do motor.
As quatro fases de verificação da abertura DHCP continuam independentes.
Nenhum resultado é reutilizado entre fases ou RPCs. O caminho comum passa de
oito para quatro observações completas; o fallback contextual Before/Target
pode exigir mais leituras e revalida o par após a verificação.

A entrada RPC exige a interface opcional conjunta, propaga o contexto restante
e permite cancelar a espera dos locks Group/Engine. Current legado mantém seu
orçamento de um segundo. Não são ampliados os prazos da concessão, confirmação
ou RPC de três segundos. Divergências físicas e efeitos incertos bloqueiam o
acesso. Não há garantia de interromper qualquer I/O de disco/kernel; a contenção
do supervisor continua necessária. Desempenho nativo após reinício pendente.
Não são criados processos, listeners, workers, dados persistentes ou API pública,
e nenhuma unidade de implantação é alterada.
