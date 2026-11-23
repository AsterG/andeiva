# Atestação de arranque após uma queda abrupta de energia

A ADR-057 exige um recibo de root que prove que o escopo agrupado anterior foi
drenado antes de outro o substituir. Uma queda de energia deixa íntegro o
registro persistido do escopo (`grouped-scope-v3`) e deixa o slot do recibo
(`grouped-retirement-v3`) vazio ou com um escopo mais antigo. A ADR-074 aprovou
uma segunda prova apenas para esse caso.

## O que o lançador faz

Antes de liberar o registro do escopo anterior, o lançador do sistema lê a
identidade de arranque do kernel diretamente do procfs e compara-a com o
registro.

A unidade empacotada aceita a montagem somente leitura de `/proc/sys/kernel`.
O lançador rejeita uma montagem separada somente leitura de toda a árvore
`/proc/sys`.

- Mesma identidade de arranque: nada é escrito. É um reinício do serviço e o
  recibo de drenagem ordenada continua obrigatório.
- Identidade de arranque diferente: o lançador escreve uma atestação de
  arranque no slot do recibo. Ela nomeia o escopo registrado, o resumo desse
  registro, as contas desta instalação e a identidade de arranque que a
  emitiu. Só então o registro é liberado e um novo escopo é criado.

A atestação nunca afirma que o escopo anterior foi drenado. Afirma que esse
escopo pertence a outro arranque do kernel da mesma instalação.

Se a energia cair de novo durante a recuperação, o armazenamento selecionado
pode ainda nomear o primeiro escopo ou já a substituição interrompida. Por
isso o lançador mantém até oito escopos registrados, do mais recente ao mais
antigo, e emite a lista novamente a cada novo arranque. Um recibo de drenagem
ordenada substitui a atestação.

## O que o helper verifica

O helper recebe o slot como descritor somente leitura vinculado por resumo ao
novo escopo. Lê por conta própria a identidade de arranque do kernel, exige que
a atestação tenha sido emitida para essa identidade e para as suas próprias
contas, e exige que o escopo nomeado pelo armazenamento selecionado seja um dos
registrados. Depois verifica o histórico selecionado completo e que o novo
escopo está fechado e vazio, tal como faz com um recibo de drenagem.

A evidência persistida com o plano de arranque leva a marca `boot_attested` e
não tem tempo de drenagem. Um armazenamento com essa evidência declara o
recurso obrigatório `configuration.routed-boot-attestation.v4`.

## O que permanece fechado

Um registro do arranque em curso sem recibo de drenagem, um registro ou slot
danificado ou adulterado, um registro ou atestação de outras contas, um escopo
que o lançador nunca registrou e um histórico selecionado corrompido mantêm o
serviço fechado e exigem manutenção offline autorizada. Web, CLI e API não
participam desta prova.

## O que o coordenador faz com a prova

Com uma prova válida para um escopo de outro arranque do kernel, um Commit ou
Confirm interrompido e um rollback que nunca terminou recebem o seu registro
terminal comum sem nenhum efeito de motor, e em seguida o Startup salvo é
iniciado no novo escopo. O prazo, a concessão e as marcas do arranque anterior
não são consultados. Uma substituição de escopo cujo arranque de Startup já
tinha sido verificado por um arranque anterior é concluída com os registros que
esse arranque deixou. Um arranque concluído e aceito por atestação acrescenta
uma entrada de auditoria protegida, `boot_attestation` com resultado
`accepted_without_receipt`. O Startup e este evento são selecionados juntos
para preservar a auditoria se houver outra queda após concluir o Startup.

Cada passo pode ser interrompido e repetido no arranque completo seguinte, com
uma exceção: uma substituição de escopo cujo próprio arranque de Startup ainda
estava selecionado quando a energia caiu de novo permanece fechada.

## Limites

O aviso ao administrador na interface web não está implementado; a entrada de
auditoria é o único registro visível. O slot é escrito no lugar: uma escrita truncada por uma queda de
energia deixa-o ilegível e o serviço fechado. Se um escopo iniciado após uma
queda parar de forma ordenada antes de o armazenamento concluir a recuperação,
o recibo de drenagem substitui a atestação e o início seguinte é recusado. As
quedas abruptas em equipamento real não foram qualificadas.

## Atualização e reversão

Antes de instalar a atualização, pare o serviço agrupado e verifique a sua
drenagem ordenada. Guarde uma cópia verificada do pacote anterior, do
armazenamento selecionado e dos registros operacionais da mesma instalação
parada. Um registro de escopo antigo só pode ser liberado com seu recibo
ordenado exato. Atestações antigas e formatos desconhecidos mantêm a
recuperação fechada.

O novo registro de escopo vincula o nó e o cutover verificado ao resumo do
slot anterior. Cada entrada retida de uma nova atestação inclui o resumo da
instalação. O helper recebe os valores esperados no seu bootstrap autenticado.
Ele verifica a origem no armazenamento, confere os MACs do gateway e compara
cada entrada com o resumo esperado.

Binários anteriores rejeitam os novos formatos de root. Para reverter, um
operador autorizado para e drena o serviço agrupado. Restaure o pacote
anterior e sua cópia verificada do estado parado pelo procedimento de
recuperação offline. Mantenha o encaminhamento fechado até verificar o Startup
restaurado e o estado do kernel. A restauração descarta as alterações
posteriores.
