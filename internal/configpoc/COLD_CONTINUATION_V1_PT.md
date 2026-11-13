# Continuação a frio limitada

`CaptureColdAnchorV1` captura o cabeçalho canônico selecionado e retorna um `RoutedColdAnchorV1` opaco, em memória e vinculado ao leitor. `Reference()` expõe apenas correlação; JSON não expõe o conteúdo privado. A captura não qualifica o histórico nem declara disponibilidade.

`ResolveColdContinuationV1` valida separadamente o fechamento de autorização atual e relê a seleção e o estado originais usando o leitor limitado e seu perfil. Verifica identidade do trabalho, prazo original, finalidade e vínculos duráveis. Permite somente compensação, confirmação e leituras existentes, retomada de trabalho estabelecido e Boot do coordenador vinculado à configuração capturada ou à sua conclusão verificada. Novos Arm/Apply comuns continuam negados até a inspeção completa.

A fronteira entre boots deve preservar configuração de origem, trabalho original e referências exatas de origem/boot anterior. Boot após reverter Pending também exige registro final real de recuperação, proprietário/origem/lease, projeção exata de rollback, cadeia de auditoria e entrada contextual do índice de recuperação. A conclusão comum com falha usa operação imutável, plano selecionado e auditoria final. Toda a configuração resultante é comparada, incluindo Startup e candidatos. Running igual não comprova procedência. O prazo de Boot permanece Started + 10 segundos original; não há duração fornecida pelo cliente ou reinício do prazo.

O chamador mantém a barreira do escritor e verifica CAS/readback do recibo físico do guardian. Esta biblioteca não inspeciona listeners nem substitui G1 completo. O limite do estado selecionado limita a âncora codificada retida; não é quota de heap. Leituras adicionais usam os orçamentos existentes por chamada. A âncora não retém descritores nem cache de objetos entre chamadas.

Os testes usam armazenamento/pools canônicos temporários reais e respostas físicas simuladas. Cobrem recuperação de Pending seguida de Boot. A integração de Intent comum interrompido permanece bloqueada pela recusa existente de R2 em retirar um plano com lease sem resolução arquivada após rollback com falha; o integrador mantém a reprodução privada. O leitor não contorna essa recusa, e os testes não qualificam essa conclusão em runtime.

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc -run '^TestColdContinuationV1' -count=1 -timeout=3m
```

Usar Go 1.27.4 e dependências offline já disponíveis. Não há alegação de qualificação implantada, de rede ou de desempenho entre usuários.


## Bloqueio persistente

ResolveFencedContinuationV1 reutiliza o mesmo grafo limitado e sua validação final. Permite compensação original e leitura efetiva; rejeita Arm, Apply, Bootstrap e Resume. Confirm exige um Intent de confirmação ou inicialização previamente selecionado, cujo conteúdo tipado completo continua igual ao da âncora. Uma âncora apenas com Pending não autoriza nova confirmação durante o bloqueio. Isso não remove o bloqueio nem comprova integridade completa. Corrupção confirmada também bloqueia todo o escritor, inclusive publicações internas de identidade e manutenção.
