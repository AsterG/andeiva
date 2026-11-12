# Acesso preparado de leitura às reservas

A biblioteca implementa um perfil explícito de leitor compartilhado e observações
limitadas de pools v2. Não ativa IPC agrupado, seleciona políticas, autoriza efeitos,
migra o appliance nem conclui a resiliência do armazenamento.

`PrepareV2` e `OpenV2` mantêm 0700/0600. R1 e o formato persistente não mudam.
`PrepareSharedV2` exige um diretório vazio previamente provisionado;
`OpenSharedV2` mantém o lock exclusivo do escritor. Não convertem permissões
existentes. Novos arquivos são criados exclusivamente e recebem 0640 mesmo com
umask 077; uma preparação malsucedida preserva os arquivos parciais.

O supervisor confiável fornece `ReaderAccessV2` versão 1: UID proprietário, GID
leitor dedicado, dispositivo e inode do diretório. Exigem-se diretórios 02750 e
arquivos 0640 exatos, proprietário/grupo esperado e ausência de ACL POSIX estendida
ou padrão. Identidade, link único, arquivo regular e mesmo dispositivo são
verificados. Consultas ACL não suportadas são rejeitadas. O leitor não pode ser
root e deve pertencer ao grupo leitor. Contas, credenciais e chaves TLS permanecem
fora dessas raízes e grupos.

`OpenReadOnlyV2` também exige ID, função, capacidade e quantidade de slots esperados.
Abre descritores de leitura sem flock, sync, reparo ou publicação. `Snapshot`
compara duas capturas limitadas dos dois bancos e conteúdos; `Revalidate` compara
outra captura com a evidência anterior. Bancos desiguais válidos preservam a
semântica de transições v2; evidência parcial, inconsistente ou variável é rejeitada.
Inventários e conteúdos retornados são cópias. O snapshot tem campos privados e
não é um token serializável de autorização.

`CheckDirectory` e `ReadFile` permitem reutilizar as verificações de arquivos.
`ReadFile` aceita um nome ASCII limitado sem caminho e um limite de 1 byte a 1 MiB;
não valida hashes de conteúdo nem relações contextuais do grafo.

O consumidor deve verificar opt-in canônico persistente, seleção, trabalho,
finalidade e bindings. Mantém a barreira do coordenador durante verificação e
efeitos; o supervisor bloqueia o controlador anterior antes de abrir outro
escritor. A leitura dupla não é CAS disco/kernel. O guardian já armado preserva o
plano verificado de reversão sem depender de novas leituras. O cancelamento é
cooperativo, não um prazo rígido de E/S. Conversão offline, binários antigos e
testes reais com três UIDs permanecem como requisitos de integração. Não há
conversão automática nem fallback para o perfil privado.

Limites existentes: 32 slots de até 1 MiB, `slots + 1` descritores retidos e um
transitório de diretório. Duas capturas podem reter quatro cópias do conteúdo por
slot; o consumidor deve orçar os snapshots retidos. O leitor não adiciona workers,
timers, cache, alocação de disco ou E/S de fundo. O perfil usual de planos tem
18 slots de 16 KiB. O benchmark mede a biblioteca, não o dimensionamento do
appliance nem a latência máxima.

Uma execução sem privilégios no WSL/Linux com Go 1.27.4 e Intel i7-1370P mediu
dez snapshots de um pool cheio de 18 slots de 16 KiB: 2,241 ms/op,
1.377.323 B/op e 7.493 alocações/op. As alocações não são o RSS do processo.
Isolamento Debian, impacto no appliance e a transação GroupIPC completa não
foram medidos aqui.

Reproduzir no Linux com Go 1.27.4, conta não root e filesystem com ACL POSIX.
Os testes usam diretórios descartáveis, não o store ativo:

```sh
go test -race ./internal/recoveryreserve -count=1 -timeout=3m
go vet ./internal/recoveryreserve
go test ./internal/recoveryreserve -run '^$' -bench BenchmarkReadOnlyV2Snapshot -benchtime=10x
```
