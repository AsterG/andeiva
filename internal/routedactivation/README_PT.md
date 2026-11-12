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

`New(Kernel, Network, localengine.Listeners, Options)` fornece o motor Group.
Kernel é transporte confiável do namespace limitado às três tabelas; observação
e remoção de listeners abrangem somente o próprio manager. Prepare retorna
`PreparationV1{Before, Target, Dependencies}` sem efeitos. Options.ResolvePlan
resolve os artefatos do Intent durável selecionado e valida deadline original,
referências contextuais e reservas. Forma ou resolver que sempre aceita não bastam.
`ObserveOwned` e `MatchOwned` retornam/verificam apenas referências selecionadas
após readback semântico físico.

A ativação inicial exige tabela schema-4 deny vazia realmente conhecida, tabela
routed ausente, IPv4 vazio e tabela local ausente ou vazia conhecida. Uma transação
nft instala deny routed/local e remove legacy antes de configurar rotas. Target
substitui deny após verificar rede e listeners próprios. A recuperação instala
deny, restaura/remove listeners próprios, restaura o memento de rede e restabelece
as tabelas anteriores atomicamente, incluindo ausência comprovada. Estado alheio
ou desconhecido bloqueia em vez de exclusão cega. Escritores exclusivos são
obrigatórios; não há atomicidade contra CAP_NET_ADMIN alheio. Edições posteriores
exigem o mesmo plano de rede.

Não há ativação runtime, provas de endpoints, recuperação durável ou adoção do
manager do host. A montagem autentica metadata e FDs. Reiniciar o helper não
reconstrói propriedade do executor a partir do snapshot. Não há novo banco,
workers ou processos: usa-se uma lease Group, até três estados por tabela e
batches nft de 512 KiB. Testes controlados exercitam compiladores e falhas.
Helper/tráfego nativos, recuperação após crash, continuidade de endpoints e
medições de recursos permanecem pendentes.

```sh
go test -race ./internal/networkexecutor ./internal/routedactivation -count=3
go vet ./internal/networkexecutor ./internal/routedactivation
```
