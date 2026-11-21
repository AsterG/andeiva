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

## Limites

Este documento cobre apenas a prova. Arquivar um Commit interrompido, um
rollback falhado ou uma substituição de escopo inacabada e selecionar Startup
para eles ainda não está implementado; esses estados continuam a parar o
arranque. O slot é escrito no lugar: uma escrita truncada por uma queda de
energia deixa-o ilegível e o serviço fechado. Se um escopo iniciado após uma
queda parar de forma ordenada antes de o armazenamento concluir a recuperação,
o recibo de drenagem substitui a atestação e o início seguinte é recusado. As
quedas abruptas em equipamento real não foram qualificadas.
