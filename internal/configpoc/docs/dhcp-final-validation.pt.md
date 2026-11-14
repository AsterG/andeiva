# Validação final da leitura DHCP selecionada

O candidato privado não é autoridade. A resolução DHCP verifica Work e identidade
e depois revalida todas as dependências consumidas, reservas físicas, seletor e
publicação pendente antes de retornar uma prova. Leitores comuns mantêm sua
validação. Nenhum cache sobrevive à chamada; o chamador mantém a barreira de
publicação/proprietário durante os efeitos.

A regressão compara `IOCalls` contabilizados com uma validação final e com a
passagem duplicada anterior; depois executa o resolvedor público no orçamento de
uma passagem. Mede trabalho contabilizado, não syscalls, CPU ou latência de disco.
Leitores completo e de ação rejeitam mudanças de seletor, Work, publicação
pendente, reservas e cancelamento. Action também rejeita uma nova dependência
lida depois do candidato; adições arbitrárias não cacheadas de Full não são
cobertas. Testes existentes cobrem preparação, aplicação e retirada. Esgotar o
orçamento durante a limpeza deve anular a prova pública. Não se afirma injeção
de erro de fechamento de FD nem desempenho nativo.

Executar em Linux/WSL com Go 1.27.4:

```sh
go test -race ./internal/configpoc -run 'TestDHCPFinalValidationV3|TestRoutedDHCPSelectedV3.*Reader' -count=1 -timeout=180s
go vet ./internal/configpoc
```

Rollback por reversão do código, sem alterar formatos ou configuração selecionada.
