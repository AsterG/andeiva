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

O consumidor experimental do mesmo boot vincula anchors herdados ao trabalho
CURRENT selecionado pelo leitor privado sem capacidades. Root mantém o
`checkpoint.lock` existente durante todo o processo. G1/R2 completo seleciona
DHCP, Boot, Pending ou Active; rejeita correspondências históricas, corrupção,
intents comuns não suportados e scopes ainda não selecionados. Não fabrica um
scope inicial antes de L2.

O caminho de cgroup vivo exige invocação não delegada, sem filhos e zero membros
no grupo antigo distinto, ou apenas Root se o mesmo grupo foi reutilizado.
A nova rota exige ENODEV sem bytes no FD original autenticado, inodes antigo e
atual distintos no mesmo dispositivo e invocações reais distintas. Revalida
seleção exata sob o lock original, sete anchors, BootID/host atuais, unidade não
delegada e drenagem com somente Root. ENOENT, leitura parcial, identidade alterada
ou qualquer prova falha recusam. Revisão independente e qualificação nativa
pendentes; a tentativa anterior parou na antiga recusa ENODEV mantendo sete FD.
Não acrescenta recuperação após reboot do OS, suspensão ou perda de energia.

Após prova selecionada e drenagem, comandos fixos fecham forwarding IPv4/IPv6,
verificam-no e removem apenas filhos MACVLAN privados reconhecidos do namespace
retido distinto do host. Revalidam o seletor antes de detach e antes de liberar
o armazenamento. Uma thread dedicada entra no mount namespace privado retido,
confere pin gateway e underlay exatos, desmonta e remove o arquivo; seu contexto
de filesystem não retorna ao pool do Go. A limpeza aceita apenas metadata exata,
netns ancorado, api vazio e os dois sockets IPC tipados. Root usa CAP_CHOWN
existente somente no diretório IPC comprovado após drenagem. Entradas desconhecidas
ou alteradas bloqueiam; sem remoção recursiva ou capacidades adicionais. Drop
verificado, fechamento de pins e conferência do lock precedem o recibo, que não
afirma rollback de endereços nem renovação do lease.

Detach/chown/unlink parcial pode exigir inspeção do operador; propriedade incerta
ou ausência de anchors não é sucesso idempotente. A retirada após queda no mesmo
boot ainda não tem qualificação nativa.

Os testes focais usam doubles explícitos do manager e transferência Unix real
para barriers. Não qualificam armazenamento systemd nativo nem teardown
privilegiado. Qualificação nativa de parada, falhas parciais,
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

## Qualificação nativa do armazenamento (opt-in)

`TestRoutedScopeRecoveryV3NativeStore` deve executar diretamente como MainPID de
`andeiva-preview-grouped.service` transitória em cliente Debian 13 isolado, onde
serviço e socket estejam ausentes. Root deve verificar `LoadState=not-found`
em ambos antes de iniciar; nunca substituir unidade instalada. O teste valida
root/sem CI, MainPID, propriedades transitórias, cgroup exato e namespace de
montagem diferente de PID1 antes dos efeitos. Cria somente gateway vazio, pequeno
diretório privado e manifest pré-alocado: sem L2, listeners, grant ou recibo.
Os sete anchors reais passam por Store/barrier/readback, VerifyStored separado,
Drop/barrier/readback vazio e Close local.

Timeout do teste 30s; unidade 45s e consultas limitadas. Root preserva o caminho
único e InvocationID. Falhas parciais de Store/Drop retêm evidências e anchors:
inspecionar antes da limpeza. SKIP ou recusa não root não qualificam sucesso
nativo. Root verifica depois armazenamento vazio, limpeza, invariantes de rede
e montagem do host e CPU/memória. Não qualifica recuperação de órfãos.

```sh
# Root preflight must show not-found for both units.
systemctl show -p LoadState andeiva-preview-grouped.service
systemctl show -p LoadState andeiva-preview-grouped.socket
# Substitute the independently verified, root-owned test artifact path.
systemd-run --unit=andeiva-preview-grouped.service --wait --pipe \
  --property=Type=exec --property=NotifyAccess=main \
  --property=FileDescriptorStoreMax=7 --property=FileDescriptorStorePreserve=yes \
  --property=PrivateMounts=yes --property=PrivateTmp=yes \
  --property=KillMode=control-group --property=NoNewPrivileges=yes \
  --property=RuntimeMaxSec=45s --property=TimeoutStopSec=3s \
  --property=TasksMax=64 --property=LimitNOFILE=256 --property=MemoryMax=256M \
  --setenv=ANDEIVA_SCOPE_STORE_NATIVE=1 \
  /ROOT_OWNED_FIXTURE/routed-scope-store-native.test \
  -test.run=^TestRoutedScopeRecoveryV3NativeStore$ -test.v -test.timeout=30s
```

A captura inicial também verifica que o manager identifica este processo Root como MainPID, o cgroup fixo e Delegate=no. O manifest registra InvocationID; rejeita controles do cgroup delegados ou graváveis por grupo/outros.

A fixture anterior Store/Drop de sete anchors passou no Debian 13 em 0.11s, com
invariantes externos do host inalterados. CPU/RAM não estavam disponíveis.
Não qualifica o novo consumidor de retirada nem suas falhas parciais.
