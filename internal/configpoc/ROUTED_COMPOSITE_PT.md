# Referências de configuração roteada

O resolvedor preparado do esquema 7 vincula firewall (esquema 4 ou 6) e serviços
locais (esquema 3). Para o esquema 6, a referência de rede deve coincidir com a
rede canônica incluída nesse mesmo firewall. O esquema 4 exige rede nula. A rede
é uma visão derivada, sem um segundo escritor.

Lê no máximo dois objetos pelo leitor limitado recebido. Verifica esquemas,
bytes canônicos e hashes, preserva erros de armazenamento e devolve referências
sem compartilhar o documento original. O esquema 5 permanece intacto e continua
rejeitando o esquema 7.

Valida somente o modelo: não migra armazenamento, expõe operações nem aplica
endereços ou regras. A integração exige Candidate/Running/Startup conjuntos,
uma autoridade de ativação, recuperação, auditoria e limites verificados.
Confirmar vários helpers separadamente não garante rollback conjunto.

As futuras operações roteadas devem incluir firewall e serviços locais no mesmo
conjunto, preservar trabalho alheio e exigir confirmação para mudanças iniciais
de rede. Save continua explícito. Validar o modelo não comprova conectividade,
disponibilidade de listeners nem autorização.

```sh
go test -race -count=1 ./internal/configpoc -run 'TestRoutedComposite|TestRoutedEnvelope'
go vet ./internal/configpoc
```

Os testes usam leitores em memória sem operações privilegiadas de rede. A
aceitação do coordenador, runtime e transição nativa permanece pendente.

[English](ROUTED_COMPOSITE.md) · [Español](ROUTED_COMPOSITE_ES.md)
