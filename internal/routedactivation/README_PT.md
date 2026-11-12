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

A ativação da fixture legacy exige tabela schema-4 canônica default-deny realmente conhecida, tabela
routed ausente, IPv4 vazio e tabela local ausente ou vazia conhecida. Uma transação
nft instala deny routed/local e remove legacy antes de configurar rotas. Target
substitui deny após verificar rede e listeners próprios. A recuperação instala
deny, restaura/remove listeners próprios, restaura o memento de rede e restabelece
as tabelas anteriores atomicamente, incluindo ausência comprovada. Estado alheio
ou desconhecido bloqueia em vez de exclusão cega. Escritores exclusivos são
obrigatórios; não há atomicidade contra CAP_NET_ADMIN alheio. Edições posteriores
exigem o mesmo plano de rede.

O supervisor provisiona a revisão schema-4 selecionada exata, incluindo suas regras,
somente no novo namespace próprio com IPv4 vazio. Readback semântico recusa regras
omitidas mesmo com comentário anunciando o hash esperado. Não redefine política
vazia nem adota tabela encontrada.

A inversão 6→4 exige Options.ResolveBaseline a partir do Work frio original:
bundle salvo, BeforeOwned físico e dependências. A referência durável de um salto
preserva lineage e encarnação do manager. Verifica revisões firewall/local exatas
e snapshot completo; ausência local não substitui listeners salvos habilitados.
Uma lease confirmada mantém deny durante retirada de listeners/rede; legacy
substitui routed atomicamente. Expiry repõe rede/listeners/regras schema-6 anteriores
sob deny. Baseline confirmado pode ativar novamente o mesmo plano. Prepare usa o
lado físico before/target real após recover, sem seletor otimista do último target.

`RecoverPlan`, exclusivo da inicialização confiável do helper, resolve o Work
original autenticado e chama RecoverPrepared com UID/GID/boot/run/namespace
target/host exatos. Root verifica lineage/generation, Intent selecionado, finality
e lease/deadline originais antes de retornar artefatos. Aceita somente a mesma
encarnação retida e baseline ou target completo após duas observações de rede.
Estado misto/alheio bloqueia sem exclusão. Não arma outro timer nem decide
reverter operações confirmadas. Reboot ou novo namespace exige Boot controlado,
sem reutilizar autoridade de ifindexes anteriores.

Não há ativação runtime, provas de endpoints, recuperação durável completa ou adoção do
manager do host. A montagem autentica metadata e FDs. Reiniciar o helper não
reconstrói propriedade do executor a partir do snapshot. Não há novo banco,
workers ou processos: usa-se uma lease Group, até três estados por tabela e
batches nft de 512 KiB. Testes controlados exercitam compiladores e falhas.
A fonte exata `3918ad8` passou tráfego/Confirm/expiry/recovery nativos em três
namespaces: wall 46.166222 s, CPU 13.259767 s e pico 31,281,152 bytes. A medição não
qualifica a extensão posterior inverse/regras legacy, reinício do helper,
recuperação após crash ou continuidade de endpoints, ainda pendentes.

```sh
go test -race ./internal/networkexecutor ./internal/routedactivation -count=3
go vet ./internal/networkexecutor ./internal/routedactivation
```

Boot schema4 sem rede usa `Options.ObservedBindings` do inventário autenticado do
supervisor e `PrepareColdBoot(target4, saved4)`. Captura `ObservedSnapshot` sem
plano desejado nem hash de plano, com ausência real das três tabelas. Boot/SystemBundle
e o prazo original Started+10s devem estar selecionados antes de aplicar.
Apply/rollback schema4 altera somente a tabela legacy: não altera endereços,
rotas, listeners ou forwarding. A expiração restaura a ausência real, não a
política Saved prospectiva. Uma edição schema4 confirmada pode diferir do Saved
original preservando o baseline observado exato. A primeira ativação schema6
compara todo o baseline com seu PreparedSnapshot real; a inversa schema6→4 ainda
exige o Saved/baseline original autenticado. Um helper novo verifica scope e
estado exatos por RecoverObserved, sem adotar namespaces encontrados ou reiniciar
temporizadores. Os testes usam compiladores/readback, Group e coordenador/reservas
duráveis reais com I/O kernel/rede simulado. Não qualificam Boot4 nativo, gestão
de interfaces existentes, DHCP ou controle do host.
