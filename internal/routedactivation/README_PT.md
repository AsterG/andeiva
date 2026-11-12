# Artefatos de ativação roteada

`OwnedV1` mantém o snapshot IPv4 preparado e a presença explícita das tabelas
fixas legacy, routed e local. Uma tabela presente exige revisão canônica completa
dos esquemas 4, 6 e 3, respectivamente; uma ausente exige revisão nil. Ausência
local abrange apenas listeners deste manager no namespace retido, sem descrever
ou alterar SSH, HTTPS ou listeners do host e de outros managers.

`DependenciesV1` vincula o plano completo aos enlaces observados, inventário local
e vizinhos confiáveis. Objetos canônicos são cópias independentes de até 256 KiB.
`PreparedSnapshot` mantém identidade, MTU, flags, endereços e rotas IPv4 observados
em até 16 KiB. O perfil inicial aceita dois enlaces planejados e loopback opcional,
com IPv4 inicialmente vazio. Recusa recursos alheios, DHCP e baselines arbitrários
já configurados.

Prepare e VerifyPrepared apenas leem. ApplyPrepared compara o baseline completo
antes dos efeitos. RestorePrepared remove somente adições registradas pela mesma
instância e verifica restauração exata com contexto independente e limitado.
Nem snapshot nem hash concedem propriedade. Ifindex é testemunho local, nunca
autorização para adotar enlaces após reiniciar.

Os artefatos ainda não oferecem ativação física do grupo, recuperação durável,
provas de endpoints ou habilitação runtime. A montagem autentica metadata e
descritores retidos; o coordenador valida Intent selecionado, contexto dos objetos
e reservas antes dos efeitos. Nenhum segundo banco de dados é introduzido.

```sh
go test -race ./internal/networkexecutor ./internal/routedactivation -count=3
go vet ./internal/networkexecutor ./internal/routedactivation
```
