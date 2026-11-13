# Inspeção da origem para migração offline

O instalador deve parar a API anterior e seu socket mantendo helper e gestor de namespaces. O núcleo mantém ambos os locks de origem até publicar a seleção. O callback não substitui esses locks nem os fingerprints exatos.

Dois papéis fixos inspecionam a origem: a identidade API sem capacidades executa apenas state/observe/state contra o helper autenticado; a identidade helper com somente NET_ADMIN entra no gateway anterior fixado por descritor e verifica semanticamente a política completa. Tabelas locais e routed administradas devem estar realmente ausentes. O perfil inicial exige zero declarações de serviços locais; não atribui listeners externos ao ANDEIVA.

O pai consulta o guardian antes e depois de inspecionar o kernel. Ambas as consultas exigem idle, mesmo PID real do helper e recibo idêntico. IDs, destinos e prazos históricos são preservados, nunca reiniciados. Nenhum papel executa Recovered, Apply, Arm ou Confirm. O handshake de leitura avança a época do controlador anterior; reiniciar essa API mantém a recuperação normal.

Solicitações limitadas a 64 KiB e respostas a 4096 bytes. Papéis fixos usam FD3 de namespace herdado, pipes de root, verificação do pai e sinal quando ele morre. Não aceita executáveis, caminhos de namespace ou comandos do chamador. Falha de leitura, substituição do helper, fase não idle ou alteração de política/recibo rejeitam a migração.

Testes com kernel simulado, compilador e verificação semântica reais e respostas modeladas do guardian. Não qualificam execução entre identidades, instalação ou kernel real. A implantação permanente permanece desabilitada até validar migração completa, inicialização e recuperação.
