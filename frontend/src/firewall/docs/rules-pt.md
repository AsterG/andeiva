# Gerenciar regras ordenadas do firewall

Abra Firewall com uma conta autorizada. A tabela mostra Rascunho local, Candidata,
Em execução ou De inicialização, conforme a seleção. A busca e o filtro de ação
reduzem as linhas exibidas sem alterar a política.

1. Selecione Rascunho local e Adicionar regra, ou selecione um ID para editar.
   Preencha origem, destino, protocolo, intervalos de portas e Permitir/Negar.
   Quando o runtime admitir o esquema 4, desmarque Habilitada para manter a regra
   sem avaliar tráfego. Salvar no rascunho local não altera servidor nem kernel.
2. Arraste o controle de seis pontos para reordenar. Pelo teclado: focalize o
   controle, pressione Espaço, escolha com setas ou Início/Fim e pressione Enter;
   Escape cancela. O menu da linha oferece Mover para posição. Limpe os filtros
   e feche o editor antes de reordenar.
3. Revise as alterações, prepare a candidata e valide. Aplicar agora ativa a
   candidata. Aplicar com confirmação adiciona um prazo: verifique a conectividade
   antes de confirmar a revisão em execução. Sem confirmação, o servidor reverte
   conforme o contrato transacional.
4. Revise Execução e Ao reiniciar. As colunas comparam cada regra exibida e sua
   posição. O estado da revisão indica se toda a revisão em execução foi salva.
   Salvar para inicialização persiste todas as regras e sua ordem.
5. O histórico permite restaurar revisões autorizadas. Após uma falha, consulte
   o estado efetivo antes de tentar outra operação.

A revisão em execução não salva pode sobreviver ao reinício do serviço pelo
registro persistente. Ela difere de Startup usada ao iniciar o appliance.
Uma regra desabilitada pode ser aplicada e salva; permanece visível sem contadores
de pacotes. Desabilitar no rascunho não tem efeito até aplicar. Contadores
desconhecidos nunca significam tráfego zero.

O tema claro é padrão; o escuro exige escolha explícita. Estes controles não
administram o firewall principal, forwarding, NAT ou interfaces de administração
fora da implantação isolada autorizada. Siga a verificação nativa da implantação
antes de considerar validados o tráfego ou a recuperação.
