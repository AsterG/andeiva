# Retenção do scope Root e retirada normal

O serviço agrupado experimental publica um manifest operacional root e sete
descritores antes de criar ou habilitar links L2. A instalação deve chamar
`PrepareRoutedScopeRecoverySlotV3` para reservar `grouped-scope-v3`: arquivo fixo
root 0600 de 4096 bytes. O runtime não cria, amplia nem sobrescreve um slot
pendente. É evidência operacional, não outro banco de configuração; G1/R2
selecionado continua obrigatório.

Os FD retêm manifest, namespace de rede gateway, namespace de montagem, arquivo
original anterior ao bind, diretório privado, cgroup original e seu
`cgroup.events`. Este último é capturado com `openat` do cgroup antes dos efeitos;
as identidades ficam registradas. Root persiste e sincroniza o manifest, envia
cada FD com `FDPOLL=0`, aguarda um barrier separado e consulta o armazenamento
real do manager. Os sete nomes, dispositivo/inode, modos e acesso devem
corresponder. O barrier sozinho não prova aceitação. Publicação parcial preserva
evidências e bloqueia efeitos; não repete nem descarta entradas desconhecidas.

A unidade usa `NotifyAccess=main`, `FileDescriptorStoreMax=7` e
`FileDescriptorStorePreserve=yes`. Root MAIN consome `LISTEN_FDNAMES` antes de
abrir outros FD: somente listener administrativo, ou listener mais os sete
anchors, em qualquer ordem. Rejeita duplicatas, conjuntos parciais, nomes
estranhos e aliases. Duplica com CLOEXEC; o supervisor mantém a validação de
namespace, interface e endereço do listener.

A parada normal exige filhos drenados e teardown explícito bem-sucedido de links
e namespace; depois remove as cópias exatas do manager, aguarda o barrier e
verifica ausência. Fecha as cópias locais retidas antes de gravar o recibo de
retirada existente. Somente recibo concluído exato e armazenamento vazio permitem
limpar o manifest. Ausência de caminhos e fechamento de FD não equivalem à
destruição RCU síncrona. Falha preserva evidência e impede recibo falso.

**A recuperação após queda continua bloqueada.** Anchors herdados são validados,
mas rejeitados antes de criar outro scope. `ENODEV`, caminho ausente, cgroup
substituto ou manifest isolado não autorizam limpeza. A observação nativa do
antigo `cgroup.events` ainda não é autoridade de retirada. Não há promessa de
persistência dos FD após reboot do OS, suspensão ou perda de energia.

Os testes focais usam doubles explícitos do manager e transferência Unix real
para barriers. Não qualificam armazenamento systemd nativo nem teardown
privilegiado. Qualificação nativa de armazenamento, parada, falhas parciais,
SIGKILL e recursos permanece pendente. Nenhum host ou appliance foi ativado.

```sh
go test -race ./internal/previewruntime -run TestRoutedScopeRecoveryV3 -count=3
go vet ./internal/previewruntime
go build ./internal/previewruntime
bash packaging/preview/tests/api-lifetime-unit-graph.sh
```

[systemd257 service FD store](https://www.freedesktop.org/software/systemd/man/257/systemd.service.html),
[named inheritance](https://www.freedesktop.org/software/systemd/man/257/sd_listen_fds.html),
[notification barriers and FDPOLL](https://www.freedesktop.org/software/systemd/man/257/sd_notify.html),
[manager readback](https://github.com/systemd/systemd/blob/v257/src/analyze/analyze-fdstore.c).
