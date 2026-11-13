# Perfis de metadados do runtime roteado

`Metadata.Validate()` e o leitor legado `ReadMetadata()` continuam aceitando somente schema 1. Esse perfil descreve host, gateway, origem e destino do laboratório: as quatro identidades de namespace devem ser distintas e não nulas. Sua representação JSON não muda.

A montagem roteada usa `Metadata.ValidateRouted()`. Aceita o validador schema 1 existente ou a seleção explícita `RoutedMetadataSchemaVersion` (2):

| Campo | Requisito do schema 2 |
| --- | --- |
| `run_id` | Identidade hexadecimal canônica de 32 caracteres em minúsculas |
| `boot_id` | UUID canônico em minúsculas, excluindo o UUID nulo |
| `host_namespace`, `gateway_namespace` | Identidades distintas e não nulas |
| `source_namespace`, `sink_namespace` | Ambos zero; não são inventados namespaces de laboratório |

Versões desconhecidas e perfis misturados são rejeitados. A ausência de origem/destino no schema 1 nunca o transforma em schema 2. Os papéis legados rejeitam schema 2. O carregador de implantação deve selecionar o perfil explicitamente e fixar de forma independente os descritores reais de host e gateway; não existe conversão automática.

A validação estrutural não concede autoridade. As verificações de descritores, processos, inicialização, pares do canal, trabalho selecionado e guardian continuam exigidas. Uma solicitação não pode substituir os metadados do supervisor. Esta extensão não altera capacidades, prazos, schemas de configuração ou rede do host.

Verificação com Go 1.27.4 do repositório:

```sh
go test -race ./internal/previewruntime -run '^(TestRoutedMetadata|TestRoutedHelperV3|TestRoutedAPIV3|TestRoutedLaunchV3|TestRoutedKernelV3)' -count=1 -timeout=3m
go test ./internal/previewruntime -run '^$' -bench '^BenchmarkRoutedMetadataV2Validation$' -benchtime=10000x
go vet ./internal/previewruntime
go build ./...
```

Os testes cobrem compatibilidade JSON, seleção explícita, decodificação estrita, substituição de identidades e rejeição de contextos de kernel/helper não vinculados. O benchmark mede somente validação pura, não dimensionamento do appliance. Este corte não qualifica implantação em dois namespaces, tráfego, transferência de interfaces do host ou recuperação em hardware real; esses continuam sendo gates de integração. Reverter requer preservar a montagem schema 1, sem forçar metadados schema 2 em um papel legado.

Uma amostra de desenvolvimento Linux com 10.000 validações puras mediu 434,7 ns por chamada, 16 bytes e uma alocação por chamada. O validador não acrescenta arquivos, descritores, processos ou caches retidos; a alocação corresponde ao analisador hexadecimal existente. Essas medidas não qualificam o desempenho do appliance.
