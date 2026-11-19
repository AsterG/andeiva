# Observação conjunta nova em cada chamada

O adaptador experimental obtém a revisão atual e a referência do estado
controlado de uma observação semântica completa sob o mesmo lock do motor.
As quatro fases de verificação da abertura DHCP continuam independentes.
Nenhum resultado é reutilizado entre fases ou RPCs. O caminho comum passa de
oito para quatro observações completas. São retornadas no máximo duas referências
coincidentes da mesma observação e do plano selecionado exato. Um alias
Before/Target exige predicados físicos canônicos idênticos byte a byte sob as
mesmas dependências; caso contrário, é recusado. Nenhuma leitura de matching
separada pode combinar estados A→B→A em uma prova falsa.

A entrada RPC exige a interface opcional conjunta, propaga o contexto restante
e permite cancelar a espera dos locks Group/Engine. Current legado mantém seu
orçamento de um segundo. Não são ampliados os prazos da concessão, confirmação
ou RPC de três segundos. Divergências físicas e efeitos incertos bloqueiam o
acesso. Não há garantia de interromper qualquer I/O de disco/kernel; a contenção
do supervisor continua necessária. Desempenho nativo após reinício pendente.
Não são criados processos, listeners, workers, dados persistentes ou API pública,
e nenhuma unidade de implantação é alterada.
