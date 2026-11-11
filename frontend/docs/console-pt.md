# Console administrativa

Antes da autenticação, apenas a tela de acesso, o logotipo original e os seletores
de idioma e tema são apresentados. Os menus e as telas administrativas são
montados após validar uma sessão vigente; são removidos ao sair, expirar ou
receber uma rejeição da sessão. Este limite visual complementa a autorização no
servidor e não substitui a autenticação nem o RBAC da API.

Abra o endereço HTTPS do appliance para entrar na console autenticada.
`/firewall` continua disponível. A navegação usa `#dashboard`, `#rules`, `#audit`,
`#configuration` e `#traffic`; mudar de tela não cria outra sessão nem prepara
configuração. Os exemplos de componentes ficam em `/?view=design-system` e não
representam o estado do appliance.

O painel calcula regras de Running e totais de pacotes/bytes da última revisão
efetiva verificada. São observações, não taxas ou conexões individuais. GeoIP,
taxas RX/TX por interface, CPU e memória ficam indisponíveis quando a API não
fornece essas observações. O mapa é geografia estática, sem fluxos ou classificação
de países inventados.

O editor lateral admite IPv4, TCP/UDP, intervalos inclusivos de portas de origem
e destino, Permitir/Negar e habilitação conforme as capacidades anunciadas.
Objetos reutilizáveis, grupos FQDN e identificação de aplicações continuam
indisponíveis. Mudar de tela preserva formulário e rascunho local; sair ou expirar
a sessão os elimina. A ordenação admite mouse, controle tátil, teclado e posição
explícita. Filtros e editor aberto impedem reordenação ambígua.

Preparar publica o rascunho como Candidate. Validar verifica Candidate; aplicar
com confirmação modifica Running e agenda reversão caso não haja confirmação.
Salvar preserva toda Running como Startup para a próxima inicialização do
sistema. Reiniciar um serviço não equivale a reiniciar o sistema. O menu de ações
inclui prazo de confirmação, Commit imediato, descarte do rascunho local e
detalhes técnicos. Descartar não remove Candidate persistida.

Auditoria exige administrador. Filtros abrangem somente a página carregada.
Datas usam o calendário local do navegador, assim como os horários visíveis.
O detalhe mostra ator, cliente, resultado e revisão completa. Expanda revisões
confirmadas para solicitar rollback. Configuração compara ordem e campos de
Candidate, Running e Startup.

Light é o padrão; Dark é escolhido e salvo explicitamente. Há EN/ES/PT e o logo
aprovado permanece intacto. Testes do navegador usam respostas de teste; não
provam autorização real ou aplicação de regras. A validação nativa no laboratório
Debian autorizado é necessária antes da implantação.

Em `frontend`, execute `npm run lint`, `npm test` e `npm run build`. Na raiz:
`docker build -f frontend/Dockerfile.visual -t andeiva-console-check .` e
`docker run --rm --network none --shm-size 256m andeiva-console-check`.

Os campos de endereço e portas do editor associam individualmente suas orientações e erros às tecnologias assistivas. Durante a reordenação, colunas, filtros, seleção de revisão e posição explícita ficam bloqueados até concluir ou cancelar. Escape cancela o movimento; a alteração permanece local até preparar a candidata.

## Versão do produto

Após entrar, abra Sistema → Sobre o ANDEIVA para consultar a versão instalada. O rodapé da navegação mostra o mesmo valor autenticado. Compilações de desenvolvimento e dados indisponíveis são indicados. A disponibilidade de atualizações não é inferida. O [guia do pacote](../../packaging/preview/docs/pt.md#versão-instalada-do-produto) explica a consulta CLI e a identidade local versus remota.
