# Trabalho DHCP selecionado (experimental)

A extensão opcional `configuration.routed-dhcp-selected.v3` usa o seletor de
configuração e os três pools de reserva existentes. Registros estáticos omitem
os campos novos; leitores anteriores rejeitam a feature obrigatória.

O trabalho vincula boot/run/namespace, revisão de rede e baseline LAN exatos,
PID/início/incarnação do proprietário, época DHCP, sequência do controlador,
deadline BOOTTIME absoluto original e endereço/rota WAN próprios. O hash serve
apenas para correlação. O leitor G1/R2 independente do helper deve emitir a
autoridade antes dos efeitos; o writer verifica o readback do helper autenticado.

Esta primeira versão fecha gate e forwarding, retira a WAN até o baseline
observado, arquiva seu R2 terminal nos dois seletores e prepara a nova concessão.
Isso interrompe a renovação: não oferece a otimização sem alterações L3 do
executor existente. As fases prepared/applied/withdrawn são auditadas. Evidência
terminal persistida impede reutilizar a mesma época/sequência. Confirm e rollback
nunca restauram um token anterior.

Reiniciar exige uma capacidade confiável de recuperação: fechar gate, resolver o
trabalho por leitura independente e retirar somente o delta WAN próprio exato.
Sem prova, com drift ou outro boot/run, a abertura é bloqueada. `withdrawn`
significa LAN original e WAN vazia observadas, não uma concessão restaurada.

Evidência atual: testes unitários com arquivos e pools reais, com autoridade de
kernel explicitamente simulada; cobrem arquivo/reutilização, replay, perda de
autoridade, fase errada e boot diferente. Runtime DHCP selecionado nativo,
bootstrap LAN e transporte autenticado ainda aguardam qualificação. A expiração
kernel pressupõe execução contínua; suspensão, pausa VM e restauração de snapshots
não são suportadas. A adoção da rede do host não é habilitada.

O perfil separado de bootstrap LAN Version 3 reutiliza Boot/R2 selecionado.
A preparação somente leitura exige ambas as interfaces IPv4 vazias. Depois de
ler a política de bloqueio aplica apenas o endereço LAN estático; WAN permanece
vazia até selecionar a concessão. O inventário local declara somente LAN.
Retirar WAN não concede propriedade LAN: restaurá-la exige o snapshot Boot
original selecionado. Testes cobrem ordem, compensação parcial e expiração Boot
sem confirmação com doubles explícitos de kernel. Qualificação nativa pendente.
