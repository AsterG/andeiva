# Requisitos de recuperação do scope Root

Este incremento experimental ainda não recupera um supervisor morto. Adiciona
captura de anchors reais, registro operacional Root de exatamente 4096 bytes,
construtor readonly e leitura real do FD store do manager. Não desmonta, remove
paths, fecha o gate DHCP ou emite recibos. G1/R2 selecionado permanece obrigatório.

`PrepareRoutedScopeRecoveryRecordV3` exige root real, BootID/host atuais, mount
namespace atual e cgroup dedicado exato sem outros processos. Recebe seis FDs
readonly: registro pré-alocado, gateway, mount namespace, underlay original antes
do bind, diretório netns root0700 e diretório cgroup2. Liga dev/inode, digest de
metadata e identidades. Root deve persistir/fsync antes de criar ou habilitar L2.
O checksum detecta escrita parcial; não autentica.

`OpenRoutedScopeRecoveryV3` verifica dono/modo/alocação do arquivo, encoding,
acesso/tipo/identidade dos FDs, scope diferente do host e BootID atual. Duplica
com CLOEXEC. `VerifyStored` executa consulta busctl fixa e limitada; exige seis
nomes exatos com modo/dev/inode/flags correspondentes. Não confia em paths ou
ordem e revalida registro/anchors depois. Prova retenção, nunca drenagem ou
permissão para emitir recibo.

Falta integrar FDSTORE com aceitação observada antes de L2; receber FDs nomeados
no próximo MAIN separando o socket administrativo; comprovar drenagem do cgroup
antigo retido; retirar o scope exato no mount namespace retido; liberar cópias do
manager e verificar ausência; somente então emitir o recibo existente. Pin ausente,
unidade renomeada, cgroup novo vazio ou manifest isolado não provam retirada.
Cgroup antigo offline/removido continua bloqueado até implementar prova de drenagem.
Parada normal também deve liberar cópias do manager antes do recibo. Falhas parciais
preservam evidência e bloqueiam.

Proposta não aplicada: `NotifyAccess=main`, `FileDescriptorStoreMax=6`,
`FileDescriptorStorePreserve=yes`. Recuperação no próximo MAIN; não presumir que
ExecStopPost recebe FDs guardados. Nomes fixos sem política, credenciais ou hash
de trabalho. Nenhuma dependência, unit, host ou appliance foi alterado. Pendentes
SIGKILL/stop/start nativos, herança FD, teardown, falhas parciais e recursos. Não
há promessa de recuperação por reboot, suspensão ou power-loss com esses FDs.

Testes: encoding, scope/fase alterados, aliases, escrita parcial, FD writable ou
tipo incorreto, recusa capless e readback incompleto/duplicado/alterado. Respostas
do manager são doubles explícitos, não evidência nativa.

```sh
go test -race ./internal/previewruntime -run TestRoutedScopeRecoveryV3 -count=1
go vet ./internal/previewruntime
go build ./internal/previewruntime
```

Fontes: [ciclo FD store systemd257](https://www.freedesktop.org/software/systemd/man/257/systemd.service.html),
[herança nomeada](https://www.freedesktop.org/software/systemd/man/257/sd_listen_fds.html),
[barrier de processamento, não aceitação](https://www.freedesktop.org/software/systemd/man/257/sd_notify.html)
e [protocolo DumpUnitFileDescriptorStore](https://github.com/systemd/systemd/blob/v257/src/analyze/analyze-fdstore.c).
