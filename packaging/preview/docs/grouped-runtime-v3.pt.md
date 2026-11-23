# Integração do runtime agrupado

O pacote contém papéis internos fixos e o preparador explícito de integridade.
Não ativa o runtime agrupado nem migra uma instalação existente. As unidades
atuais mantêm seu modo configurado. Não execute os papéis filhos manualmente:
exigem descritores herdados, pai root autenticado e credenciais exatas.

A fábrica produtiva reutiliza contas, auditoria protegida, certificado TLS,
endereço administrativo autorizado e frontend reais. Abre um único escritor v2
e leitores independentes do helper. Não abre outro escritor v1 nem inventa
Startup. Os listeners locais permanecem desabilitados neste perfil inicial.

Apenas a API recebe o socket administrativo; apenas o helper recebe seu
diretório privado de integridade. Endereço, interface e namespace do socket são
verificados, mantendo TLS e restrições de origem. HTTPS disponível não significa
configuração qualificada: a saúde exige integridade completa e leitura efetiva
inativa. Pending ou reconciliação não são estados saudáveis.

## Instalação offline pendente

O carregador de implantação e a migração offline ainda não são instalados.
Deverão parar o escritor anterior, verificar a liberação de seu bloqueio e
preservar Running, Startup, Candidate, histórico e credenciais. Validarão o
esquema real e as identidades duráveis; recusarão estados incompatíveis ou
pendentes.

A preparação usará as APIs de migração aprovadas para o armazenamento v2,
três perfis exatos de reservas e ativação explícita dos contratos agrupados,
prazos absolutos e leitor compartilhado. Raízes e device/inode serão fixados
com orçamentos aprovados, sem aumentos silenciosos. O preparador sem capacidades
criará exclusivamente o marcador em um diretório 0700 já pertencente ao helper;
não reiniciará nem reparará um marcador existente.

É necessário um namespace isolado novo e autorizado, com duas interfaces reais
compatíveis. Não se transformará a instância antiga com endereços em uma base
vazia nem serão removidas suas regras. Nenhuma rota ou interface do host muda.
A validação final exige inspeção completa, Startup autorizado e ruleset real;
falhas preservam evidências e a implantação anterior.

Build reproduzível e validação estática do pacote não demonstram migração,
inicialização nativa nem tráfego de ponta a ponta.

A inicialização e drenagem dos filhos têm um limite separado de 45 segundos para a inspeção completa de 30 segundos. Os RPC de efeitos mantêm três segundos; os prazos persistidos e Boot Started+10 segundos não mudam. A fábrica mantém a validação completa inicial e não deduz integridade de um socket aberto.

A inicialização de API/helper/namespaces legados é recusada quando existe o marcador root grouped-cutover.json, mesmo ilegível, truncado ou como link pendente. O guard não interrompe um escritor em execução: a ativação deve pará-lo, recolher seus processos e manter seu bloqueio antes. Instalar o pacote não cria o marcador.

A ativação preserva o armazenamento clássico e seus backups. Após a
publicação do marcador, voltar ao modo clássico exige recuperação offline
autorizada de um backup consistente anterior à transição. Ainda não há
comando para retornar ao modo clássico.

A ativação offline usa um processo filho privado com a identidade da API e
sem capacidades. Ele autentica o pai root pelos pipes herdados, lê o
armazenamento clássico sob o bloqueio de escrita existente e confirma
novamente a impressão digital antes da publicação. O filho usa apenas o
armazenamento clássico e seu bloqueio. O instalador verifica o escopo e a
inicialização, a drenagem dos serviços e o fechamento do encaminhamento.
Se o filho for interrompido, a inicialização clássica continua inibida e a
ativação precisa revalidar toda a preparação antes de prosseguir.

Em uma instalação Debian Preview autorizada, execute como root
`/usr/lib/andeiva-preview/andeiva-preview grouped-activate` durante a janela
fria aprovada. Pare antes a API e o socket clássicos. Os registros preparados
e os slots de recuperação devem existir. A configuração do socket agrupado
deve corresponder à configuração de gerenciamento. O comando verifica o
escopo clássico e o encaminhamento do host, mascara os dois conjuntos de
unidades de forma persistente e valida Startup com o leitor somente leitura
antes de publicar o marcador. Verifica a liberação do bloqueio antes de
iniciar o serviço. Depois verifica a integridade do serviço e o certificado TLS.

Uma impressão digital rejeitada ou uma falha do processo mantém as unidades
mascaradas. Repita uma tentativa interrompida antes da publicação usando a
mesma preparação. O instalador confere qualquer marcador pendente com os
bytes esperados. Com um marcador publicado, recusa outra ativação inicial.
Preserve o marcador para recuperação offline autorizada.
