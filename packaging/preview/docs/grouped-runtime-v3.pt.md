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
