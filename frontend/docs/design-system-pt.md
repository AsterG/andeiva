# Design System do ANDEIVA

[English](../DESIGN_SYSTEM.md) · [Español](design-system-es.md) · Português

O Design System define a aparência e os componentes compartilhados do frontend.
A página de componentes é um ambiente de demonstração da interface: seus exemplos
não administram o appliance, não aplicam regras e não representam métricas reais
de tráfego. A [auditoria](../DESIGN_AUDIT.md) descreve os problemas do frontend
anterior e suas causas.

## Temas e preferência

Light é sempre o tema inicial quando não existe uma escolha válida salva, mesmo
que o Windows ou o navegador prefiram Dark. Dark é ativado somente por uma escolha
explícita. A preferência usa `andeiva.preview.theme` no armazenamento local do
navegador; não é uma configuração do servidor nem de uma conta autenticada.

A inicialização anterior à renderização aplica o tema ao elemento `html`.
Os componentes, o fundo do documento e os diálogos consomem esse mesmo tema.
Se o armazenamento estiver indisponível, a interface continua funcionando: a
escolha permanece durante a página atual, mas não há promessa de persistência
entre sessões. Valores desconhecidos voltam para Light. Não introduzir consultas
a `prefers-color-scheme` para alterar automaticamente a aparência.

## Fontes compartilhadas

| Recurso | Responsabilidade |
| --- | --- |
| `src/design-system/tokens.css` | Cores semânticas dos dois temas, sombras, espaçamento, raios e tipografia |
| `src/design-system/components.tsx` | Componentes reutilizáveis e semântica de interação |
| `src/design-system/components.css` | Estilos dos componentes por meio de tokens |
| `src/styles.css` | Composição responsiva da aplicação; não uma paleta independente |
| `src/preferences.ts` | Validação e persistência da escolha |
| `public/theme-init.js` | Aplicação da preferência antes da primeira renderização |
| `public/andeiva-logo.png` | Logotipo oficial, sem modificações |

Os valores de cor pertencem ao arquivo de tokens. Os módulos usam seus papéis
semânticos, como `--color-background`, `--color-surface`, `--color-text`,
`--color-border-control` e `--color-button-primary`. Não devem redefinir esses
papéis localmente para criar um terceiro tema. Um novo estado visual exige um
token compartilhado ou uma extensão documentada dos tokens existentes, com uma
combinação válida em Light e Dark.

A paleta corporativa preserva branco, azul gelo, azul elétrico, ciano e azul
marinho. Cores de ações, texto e estados podem ser derivadas dessa identidade,
com contraste medido. Por exemplo, o azul elétrico original com texto branco não
atinge 4,5:1; o botão primário de Light usa um azul derivado para manter a
legibilidade. Uma borda decorativa suave não substitui a borda de um controle
quando ela é necessária para identificá-lo.

## Logotipo

O PNG aprovado contém um fundo claro. Sua superfície de branding permanece clara
de maneira deliberada nos dois temas; é uma exceção identificada por tokens, com
tamanho contido, e não um fundo branco acidental no restante da interface.
Proporção, conteúdo e bytes originais são preservados. Não aplicar `filter`,
recoloração, recorte ou deformação para simular uma variante Dark.

SHA-256 esperado:

```text
1f79f5ec7f33327c9285c702b63fc5c5a618a28395b2161d594001fdb0199f81
```

## Adicionar um módulo

1. Usar as superfícies, navegação, botões, campos, filtros, indicadores, tabelas e
   diálogos compartilhados. Não copiar seus estilos para dentro do módulo.
2. Separar a composição do módulo de sua aparência semântica. Consumir as escalas
   de espaçamento, raios e tipografia; manter os controles utilizáveis sem depender
   de uma largura fixa de desktop.
3. Adicionar todos os textos em EN/ES/PT. Usar rótulos associados aos controles,
   instruções e erros vinculados com `aria-describedby` e `aria-invalid` quando
   necessário. Não substituir um rótulo por um placeholder.
4. Manter cabeçalhos e captions de tabelas, ordem de leitura, navegação por teclado,
   foco visível e devolução do foco ao fechar um diálogo. Estados precisam de texto
   ou símbolos além de cor. Gráficos precisam de legendas e de uma alternativa
   textual compreensível.
5. Testar todos os estados do componente nos dois temas: inicial, hover, foco,
   selecionado, vazio, inválido, desabilitado e aberto, conforme aplicável.
6. Atualizar os testes e revisar as capturas antes de integrar a mudança. Não
   aprovar um componente validado somente em Light ou somente em Dark.

Essas regras são obrigatórias para firewall, NAT, VPN, SD-WAN, QoS, Security
Profiles, IDS/IPS, antivírus, WAF, DNS, logs, filtros avançados, PCAP,
administração, configuração transacional e sistema/atualizações. Sua menção não
significa que esses módulos estejam implementados.

## Validação reproduzível

A partir da raiz do repositório, com as versões de Node e npm indicadas no README:

```bash
npm --prefix frontend ci --ignore-scripts --no-audit --no-fund
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build
```

Para os testes de navegador e capturas, usar a imagem canônica do repositório:

```bash
docker build -f frontend/Dockerfile.visual -t andeiva-design-check .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true --shm-size=512m andeiva-design-check
```

`frontend/Dockerfile.visual` fixa por digest o Playwright 1.65.0 sobre Linux Noble
e o Node 24.20.0. Node e seus npm/npx 11.19.0 compartilham um diretório isolado;
o build verifica os destinos dos executáveis e imprime as três versões. A busca
normaliza maiúsculas sem depender do locale do navegador, com testes em navegador
turco e interface EN/ES/PT; não remove acentos.
O CI usa a mesma construção. A imagem executa
`npm run test:e2e`; a configuração inicia o servidor local de testes, sem backend,
portas publicadas ou acesso ao laboratório de rede. A construção precisa baixar
suas imagens e dependências quando não estiverem em cache; a execução dos testes
não tem acesso a redes externas.

Executar a comparação nesse ambiente evita confundir diferenças de fontes ou
renderização de outro sistema operacional com uma regressão do produto. Um
navegador local serve para investigar, mas não substitui o ambiente das referências.

As referências visuais ficam em `e2e/snapshots/`, separadas por viewport, tema e
tela. Quando uma alteração visual for intencional, regenerá-las somente no
ambiente canônico e revisar as mudanças:

```bash
docker create --name andeiva-design-baselines --network none --cap-drop ALL --security-opt no-new-privileges:true --shm-size=512m andeiva-design-check npm run test:visual:update
docker start --attach andeiva-design-baselines
docker cp andeiva-design-baselines:/work/frontend/e2e/snapshots frontend/e2e/
docker rm andeiva-design-baselines
```

Usar um nome de contêiner livre. Não prosseguir com a cópia se a geração falhar.
Revisar as imagens e o diff; depois reconstruir a imagem e repetir a comparação
normal com os dois comandos anteriores. A reconstrução inclui as novas
referências na imagem que executará os testes.

Não regenerar referências automaticamente para resolver uma falha de CI nem
ocultar regiões temáticas com máscaras. As verificações incluem preferências,
tokens, pares de contraste, acessibilidade automatizada, teclado, idiomas e
layouts de desktop, tablet e celular. As capturas correspondem a renderizações
reais.

O objetivo é WCAG 2.2 AA, mas os testes automatizados não certificam conformidade
completa por si só nem substituem uma avaliação com tecnologias assistivas.
Resultados executados, versões e limitações devem acompanhar cada revisão. Não
atribuir um teste de leitor de tela a uma inspeção da árvore de acessibilidade.
Medir a mudança no tamanho do bundle quando o frontend for ampliado; os navegadores
de teste não fazem parte do runtime do produto.
