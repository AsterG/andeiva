# Qualificação do core de retirada de scope

Estado: fixture implementada; qualificação nativa e medições pendentes. Um skip sem
privilégios não comprova qualificação nativa.
O primeiro teste nativo falhou antes de Store ou efeitos de rede: os API
filesystems ocultaram `/run/andeiva-preview/grouped`. O segundo bind filho usava
uma origem dentro da árvore oculta e falhou NAMESPACE/226 antes de executar Go.
Ambos preservaram FDstore vazio; a retirada não passou. Agora todo o `/run`
privado da fixture é montado com `norbind`, substituindo o fallback MountAPIVFS
no mesmo destino. A repetição nativa continua pendente.

Somente Root, em laboratório Debian 13 autorizado sem
`andeiva-preview-grouped.service` nem seu socket. Não executar em CI, WSL
privilegiado ou appliance instalado. Duas invocações reais: a primeira persiste
sete anchors antes de L2/Boot, inicia API sem capacidades/helper com NET_ADMIN,
verifica Boot/readback, espera os filhos e encerra a si mesma com SIGKILL.
A segunda recebe sete FD, testa recusa com lock ocupado e executa o core real
com leitor capless, G1/R2, drain, desmontagem, Drop e recibo. A terceira tentativa
chegou a Store/Boot real e parou na antiga recusa ENODEV, preservando sete FD.
O core novo exige revalidação de seleção, anchors, boot/namespace, unidade atual
e drenagem; revisão e teste nativo pendentes. Marcadores por InvocationID preservam
falhas anteriores. Root pode tentar novamente a unidade retida com binário
revisado e invocação nova real; isso não qualifica o contador do driver de unidade
nova nem o handoff management.

RootDirectory e passwd/group privados; pais veth e MACVLAN somente em namespaces
isolados. O bind writable de `/run` vem somente da raiz temporária, nunca do
`/run` do host, com caminho canônico e owner/modo verificados. Os sockets do
manager mantêm binds separados somente leitura; `/var/lib` também fica nessa raiz.
Nenhum RuntimeDirectory é criado no host. Pais e links permanecem
isolados, sem endereços, rotas ou regras do host. Os pais modelam links externos
e não fazem parte do recibo do gateway. Seus pins ficam no MNT privado antigo.
A projeção operacional schema2 preserva exatamente Boot/Run/Host/GW do bootstrap
schema1; não altera a identidade selecionada.

Escopo: core com raízes reais fornecidas diretamente. Não qualifica loader,
procedência de migração, restart managed, reboot ou handoff management de oito
FD. A árvore de integração precisa do dispatch TestMain do preflight e consultas
fixas systemctl com `SYSTEMD_OFFLINE=0` dentro de RootDirectory; LocalOrigin não
é enfraquecido.
RootDirectory, PrivateMounts, MainPID e InvocationID são consultados no manager
real; sem leitura de symlinks do PID1 ou SYS_PTRACE adicional. O driver rejeita
aliases de caminho por comparação canônica e exige PASS/exit da invocação atual.

```sh
go test -race ./internal/previewruntime -run '^TestRoutedScopeRetireV3Native' -count=1 -v
go vet ./internal/previewruntime
go test -c ./internal/previewruntime -o /absolute/output/scope-retire.test
bash -n packaging/preview/tests/scope-retire-native.sh
# Somente Root, após revisão do artefato e invariantes:
bash packaging/preview/tests/scope-retire-native.sh --isolated-lab /root-owned-0755-directory/scope-retire.test
```

Limites: duas invocações, timeout de teste 90 segundos, 256 FD, 128 tarefas,
384 MiB. SYS_ADMIN pertence à fixture, não ao helper. Falhas preservam unidade,
FDstore, manifest, slot e arquivos; sem stop automático ou remoção recursiva.
Sucesso exige segunda InvocationID correlacionada, FDstore vazio e MainPID zero
antes de parar essa unidade. Preservar journal, propriedades, hashes e recibo.
Root deve comparar endereços/rotas/rules IPv4/IPv6, nftables, forwarding,
namespaces e mountinfo do PID1, registrando CPU/RAM reais.

Enquanto a recuperação precisar dos descritores retidos, não executar
`reset-failed`, parar nem recriar a unidade transitória que falhou. Um
`reset-failed` observado causou a coleta da unidade pelo manager e a perda dos
sete descritores. O manifest restante não autoriza adoção nem recibo de retirada.
Preservar a evidência original; uma tentativa direta após expirar o limite de
partidas exige verificar os descritores retidos e uma nova invocação real.
As verificações de sucesso deste driver para uma unidade nova não qualificam
essa tentativa.

Erros de recuperação Root identificam etapas fixas e preservam a causa.
A execução do scope retido com fonte `b0eeaec` falhou especificamente em
`detach namespace: enter retained mount namespace` com `EPERM`; preservou sete
descritores do manager e a captura original, sem emitir recibo. A fixture
adiciona somente `CAP_SYS_CHROOT`, necessária junto com `CAP_SYS_ADMIN` para
entrar no mount namespace ([setns(2)](https://manpages.debian.org/trixie/manpages-dev/setns.2.en.html)).
Uma verificação das capacidades efetivas/permitidas e negativas unitárias por
capacidade ausente precedem os efeitos. Não substituem essa evidência nativa
negativa nem qualificam uma retirada bem-sucedida com o novo orçamento.
Nenhum helper ganha capacidades.

[English](en.md) · [Español](es.md)

## Resultado observado do componente

Uma execução autorizada em Debian 13 amd64 completou duas invocações: o primeiro processo root armazenou sete anchors e foi interrompido; o substituto verificou a configuração selecionada sob o lock original, drenou processos, retirou o gateway, verificou FD store vazio e publicou o recibo exato. O harness exigiu um reinício automático e parou a unidade somente após sucesso. Endereços, rotas, regras, forwarding, namespaces e montagens do host coincidiram.

A recuperação levou 0,67 s; sua invocação registrou CPU acumulada de 0,541928 s e pico de memória cgroup de 12.828.672 bytes. São medidas do harness, não do appliance estável. A negativa anterior sem a capacidade necessária falhou ao entrar no namespace de montagem, preservou sete anchors e não produziu recibo. Entrada e restauração exigem CAP_SYS_CHROOT junto com CAP_SYS_ADMIN; os orçamentos de API/helper não mudam.

Permanecem pendentes procedência do loader instalado, ativação administrativa de oito descritores, reboot gerenciado e interrupções em cada etapa de teardown. Esse resultado não encerra recuperação do appliance nem o marco Firewall & Routing.