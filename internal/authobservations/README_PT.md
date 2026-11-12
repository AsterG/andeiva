# Observações de autenticação anônima

Componente Linux preparado, com ativação explícita; nenhum runtime do appliance
o habilita. `adminauth.New` mantém a auditoria protegida existente.
[English](README.md) · [Español](README_ES.md).

`adminauth.NewWithAnonymousObservations` classifica somente novas falhas de login
anteriores à verificação da credencial. Agrega por minuto UTC e endereço real do
socket receptor. Normaliza IPv4 representado como IPv6; não usa portas, cabeçalhos
encaminhados, nomes de usuário, credenciais ou tokens como chaves. Tentativas
internas sem socket e pares inválidos entram no contador de excesso sem
atribuição. Não adiciona observações a outras falhas anônimas da API.

Verificação bem-sucedida, negativas por limites de login/sessões após verificar
a credencial, logout, revogações e negativas administrativas continuam na
auditoria protegida. Sua falha continua bloqueando a autorização. Falha da área
anônima não autentica o solicitante nem marca a auditoria protegida como falha.
Nenhum evento histórico, incluindo negativas antigas de login, é reclassificado
ou modificado. Não há autoridade nova para exportar, reconhecer ou apagar
auditoria protegida.

## Admissão e propriedade

O integrador confiável fornece um `os.Root` dedicado, previamente aberto,
pertencente ao processo e com modo 0700, além de um `AdmissionGuard` obrigatório.
`Prepare` exige área vazia; sincroniza snapshot e política versionados antes de
selecionar `policy.json` por rename atômico. `Open` exige essa seleção e um bloqueio
exclusivo existente. Arquivos são regulares, com um link, modo 0600 e o mesmo
proprietário. Entradas desconhecidas, links simbólicos, dados malformados e
versões não suportadas são rejeitados. O chamador mantém o descritor raiz.
`Close` encerra e aguarda o worker, libera o bloqueio e retorna erros de publicação.

`AdmissionGuard.Selection` deve verificar a seleção real do runtime, ausência de
escritores durante a preparação, inventário histórico protegido e backup
idênticos, e exclusão de escritores incompatíveis. Depois deve verificar a
seleção ativa exata. Os hashes identificam o inventário histórico capturado;
não impedem novos eventos protegidos. Não existe provedor permissivo nem
integração implantada desse guard. Um novo diretório ou arquivo de política não
impede sozinho que um binário antigo ignore a migração. O runtime deverá rejeitar
seleções incompatíveis antes de construir escritores; essa qualificação está
pendente. Os testes de rejeição cobrem a interface, não um executável antigo
implantado.

`AdmissionGuard.Capacity` deve comprovar isolamento em relação à auditoria e
recuperação protegidas. Diretórios separados e espaço disponível observado não
criam isolamento. O módulo não implementa quotas, reservas físicas ou reserva
de auditoria protegida.

Se `Open` não recuperar a área anônima, `OpenDegraded` exige uma `Selection`
canônica exata fornecida pelo estado confiável independente do runtime,
validada pelo guard contra a identidade real da área e a seleção compatível.
Nunca deduz a seleção de arquivos de observação corrompidos. Não abre arquivos
de dados nem inicia worker; não pode escrever, apagar ou reparar. Agrega somente
em memória limitada e informa `memory_only`, `degraded` e `unknown_gap`;
`allocated_known=false` e `persisted_through` zero evitam inventar medições ou
histórico. A autenticação verificada continua exigindo auditoria protegida.
Seleção canônica ausente ou incompatível impede admissão; não há retorno a legacy.

## Limites, publicação e perdas

- Máximo de 1.440 intervalos e 512 entradas de par/minuto no total. Detalhes acima
  da cardinalidade entram no contador de excesso; totais retidos continuam.
- Expiração 24 horas após criar cada intervalo. O limite de cardinalidade pode
  reduzir a cobertura. Expiração e descarte por capacidade ficam visíveis.
- Teto de 4 MiB para a área própria e snapshots de até 512 KiB. A contagem inclui
  blocos Linux dos arquivos nomeados e diretório. Antes de publicar, considera
  o temporário coexistente, 64 KiB para metadados, blocos e inode disponíveis.
  Isso não é quota, reserva contra terceiros ou custo total do filesystem.
- Um worker por minuto publica somente alterações e agenda expiração. `Record`
  não faz I/O. Autenticação legacy não cria esse worker.
- Publicação com temporário novo, sincronização e rename. Resultado incerto
  bloqueia novas publicações até reabrir. Um temporário válido não selecionado
  da geração seguinte pode ser removido na reabertura; um parcial ou inválido
  é preservado e bloqueia a abertura. Alterações externas na seleção são rejeitadas.

Relatórios são limites inferiores, não registros exatos após uma falha.
`persisted_through` identifica a última publicação reconhecida; `pending`,
`unknown_gap`, `degraded`, excesso e contadores saturáveis mostram as limitações.
Toda reabertura informa uma lacuna desconhecida. Não se inventam quantidades de
tentativas perdidas sem sincronização. Leituras excluem detalhes expirados mesmo
sob pressão. Não há garantia de remoção física enquanto o processo estiver
parado ou o volume somente leitura. Cancelamento é cooperativo, sem prazo rígido
para chamadas ao filesystem. Seleção corrompida nunca equivale a armazenamento vazio.

A expiração depende de relógio UTC confiável. Um retrocesso rejeita novas
observações ou marca o relatório degradado; não comprova 24 horas reais
transcorridas entre reinícios ou falhas do relógio. Essa dependência precisa ser qualificada.

`Manager.AnonymousObservations` exige sessão admin válida e permite somente
leitura. Não adiciona rotas HTTP ou permissões de escrita. Permanecem pendentes
ativação Web/CLI/API, pressão física real, isolamento de reservas e desempenho
do appliance. Este componente não encerra AND01/AND02.

## Testes e escopo medido

Com Go 1.27.4 e dependências previamente disponibilizadas, na raiz:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -race -mod=readonly -buildvcs=false ./internal/authobservations ./internal/adminauth -count=3
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go vet -mod=readonly -buildvcs=false ./internal/authobservations ./internal/adminauth
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go build -mod=readonly -buildvcs=false ./internal/authobservations ./internal/adminauth
go test -mod=readonly -buildvcs=false ./internal/authobservations -run TestObservationsBoundedResourceSample -bench BenchmarkObservationsExistingPeer -benchmem -v
```

Os testes cobrem compatibilidade dos eventos protegidos, admissão, admin/viewer,
concorrência, pressão por guard injetado, cardinalidade, idade/relógio, arquivos
alterados, publicação interrompida e saída/reabertura de processo filho.
Também verificam login auditado com snapshot corrompido e coleta em memória
admitida independentemente. Não testam perda elétrica ou reserva implantada.
Uma amostra Linux/WSL com 1.440
intervalos e 512 entradas ocupou snapshot de 175.945 bytes e 184.320 bytes
alocados observados. O microbenchmark de par existente mediu 116,2 ns/op,
16 B/op e uma alocação/op. Não são RAM do appliance, desempenho contínuo ou
dimensionamento de produção.
