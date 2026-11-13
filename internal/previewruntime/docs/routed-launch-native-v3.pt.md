# Fixture nativo de inicialização agrupada V3

Estado: integração bloqueada antes da prontidão da API. Este fixture não é uma implantação de produção nem uma qualificação de tráfego.

`TestNativeRoutedLaunchV3` utiliza o launcher e ambas as factories V3 reais. Um processo separado com identidade API e sem capacidades prepara offline o armazenamento declarado e pools reais; fecha os escritores antes de converter o perfil leitor. O helper usa adaptadores físicos, observa ausência real de listeners e exige ausência das três tabelas gerenciadas antes da inicialização. Nenhum simulador fornece readback. O slot obrigatório do motor local rejeita todas as ações e seu contador deve permanecer em zero.

As verificações positivas previstas incluem UID/GID/grupos exatos, cinco conjuntos de capacidades, no-new-privileges, namespaces distintos, descritores leitores, acesso negado do helper às credenciais e ao lock escritor, autenticação real do peer V3, boot/readback agrupado, HTTPS com certificado verificado, rejeição anônima, leitura autenticada e reinicialização da API preservando o PID do helper. Dois pares veth isolados conectam o gateway a peers descartáveis; ambas as pontas ficam ativas sem endereços ou rotas IPv4. Nenhum link do host é alterado e o tráfego IPv6 não é qualificado. Não se comprova tráfego encaminhado, morte durante operação pendente, recuperação entre inicializações do SO ou limpeza de descendentes durante comando de kernel interrompido.

Compilar no Linux com o toolchain do repositório:

```sh
go test -c -o previewruntime.test ./internal/previewruntime
go vet ./internal/previewruntime
bash -n packaging/preview/tests/routed-launch-native.sh
```

Transferir pela conexão aprovada do laboratório com identidade fixada e verificar hashes. Instalar em novo diretório root com modo 0755; binário 0755 e script 0700. Executar somente no cliente Debian 13 autorizado, em unidade root com `PrivateMounts=yes`, `TemporaryFileSystem=/run/netns:mode=0755`, `ProtectSystem=strict`, `ReadWritePaths` limitado ao diretório do fixture, `KillMode=control-group`, `LimitNOFILE=256`, `TimeoutStopSec=5s` e `RuntimeMaxSec=110s`. Comando da unidade:

```sh
bash /APPROVED_FIXTURE/run.sh --isolated-lab /APPROVED_FIXTURE/fixture.test
```

O harness gera nomes únicos e verifica inodos antes da limpeza. Recusa remover namespaces com processos presentes; a unidade continua responsável pela limpeza dos descendentes. Preservar binário/logs da falha e usar outra unidade/diretório na próxima tentativa.

Tentativa observada, 2026-11-12: binário SHA-256 `501a99e6d02b071b370108cad6947b7e29ba4ac7652516fe8bec1664eba4232f`, script SHA-256 `6c4e4707229c9c636c38ba55f4b2feb2f6e9f453d396f8fc72d787a78f95bbfc`. Helper: UID 62002, GID 62003, grupo suplementar 62004, somente NET_ADMIN nos cinco conjuntos, NNP=1 e 57 descritores de pools somente leitura. A API não chegou à prontidão: `ANDEIVA_OPERATION_UNAVAILABLE`. Unidade exit-code 1; duração 427 ms, CPU 290395000 ns, pico de memória 30687232 bytes. São medidas de inicialização com falha, não do orçamento operacional. As comparações de regras, rotas e forwarding do host passaram e não restaram namespaces nomeados, conforme o orquestrador que executou a unidade remota.

O binário de diagnóstico adiciona nomes fixos de etapas sem credenciais ou corpos de configuração. Compilação, vet e sintaxe shell passaram. Sucesso nativo completo e revisão da fonte final permanecem pendentes. Nenhuma implantação Docker/EKS adicionada.

## Qualificação nativa após as correções

Uma execução posterior no Debian 13 passou o fixture completo em 1,86 s: identidades API/helper distintas, API sem capacidades, helper somente CAP_NET_ADMIN, rejeição de leitura cruzada, boot/readback físico agrupado, HTTPS com certificado verificado (401 anônimo/200 autenticado) e reinicialização da API preservando o helper. Limpeza aprovada; rotas, regras nft e forwarding IPv4 do host permaneceram idênticos. A unidade completa consumiu 1,907755 s de CPU e pico de 40.755.200 bytes, incluindo preparação e processos; não representa RSS ocioso nem dimensionamento de produção. SHA-256 do binário: ac41c85bff907010f05859085eb5d242047c72ff55c3340189e20999ad9e6a43; do harness: 3e6188272e2d6663f287b08373e6aa655c31be8a15af2ed63b98c46d5b1c6f5b.

A falha anterior revelou que a leitura do proprietário exigia incorretamente o grupo leitor do helper; agora mantêm controles de identidade separados. Os links dummy desativados foram substituídos por peers veth isolados e ativos, sem relaxar a validação. Não se comprovaram tráfego encaminhado, prazos sob carga, interfaces principais, instalação ou recuperação após reinicialização do SO.


Para o perfil explícito de integridade, use o mesmo namespace de montagem privado e cgroup próprio com --isolated-integrity-lab TEST_BINARY. Seleciona TestNativeRoutedIntegrityLaunchV3, incluindo o papel fixo de preparação sem capacidades e o diretório persistente exclusivo do helper. A seleção anterior --isolated-lab permanece inalterada. Não ativa um serviço instalado nem comprova tráfego roteado de clientes.
