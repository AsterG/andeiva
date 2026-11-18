# IDs duráveis de sub-rede DHCP

Registro operacional interno separado de configuração e leases; ainda não ligado
ao runtime. Bootstrap confiável fornece os FDs do diretório protegido e do filho
fixo `leases`; a API não escolhe caminhos. Raiz prevista:
`/var/lib/andeiva-preview-package/dhcp-server`, root:root 0700. O arquivo
`scope-bindings.v1.json` exige root:root 0600. Leases exige 0700; bootstrap ainda
deve verificar o proprietário do motor mantido.

A chave contém scope ID, ID da interface LAN selecionada, MAC física e sub-rede
IPv4 canônica. Alterar pools ou opções mantém o ID; outra interface, MAC ou
sub-rede recebe outro uint32 não nulo. A alocação cresce sem reutilização e mantém
mapeamentos removidos, inclusive ao desabilitar, reabilitar ou reverter a
configuração. A ordem do lote não altera a atribuição. Limites: 4096 entradas e 1 MiB.

Flock independente do diretório serializa chamadas. Criação exclusiva sem seguir
links, fsync do arquivo, rename atômico e fsync do diretório precedem o retorno de
IDs. Se a persistência falhar, o registro não retorna IDs e o motor não pode
iniciar. Se o rename estiver visível após uma falha no fsync do diretório, a
próxima tentativa precisa sincronizar o diretório sob bloqueio para retornar IDs.
Um arquivo pendente bloqueia as chamadas até a recuperação protegida.
Cancelamento é cooperativo, sem garantia temporal de disco. O registro nunca
interrompe o serviço existente.

Sem registro, qualquer lease existente impede inicialização. Somente um diretório
de leases vazio e bloqueado permite inicializar. No limite, chaves existentes
continuam consultáveis sem escrita; novas alocações falham. Escritas parciais
incertas bloqueiam resolução até recuperação protegida. Não há reparo automático.
Restauração ou remoção arbitrária por root não é detectável sem âncora monotônica
externa; rollback de configuração nunca deve restaurar este registro separado
de seu histórico de leases.

Linux/WSL, Go 1.27.4:

```sh
go test -race ./internal/previewruntime -run '^TestDHCPSubnetRegistryV1' -count=1
go vet ./internal/previewruntime
go build ./internal/previewruntime
go test -c -o /tmp/andeiva-dhcp-subnet-registry.test ./internal/previewruntime
```

Fixture de filesystem root opt-in: `ANDEIVA_NATIVE_DHCP_SUBNET_REGISTRY=1`, filtro
`^TestDHCPSubnetRegistryV1RootLifecycleNative$`. Cria e remove apenas seu diretório
temporário; não inicia DHCP nem altera rede. Não qualifica lifecycle, leases,
queda de energia ou recursos produtivos; essas provas nativas/integradas estão
pendentes. Reverter código deve preservar registro e leases; não existe migração
para downgrade ou reutilização de IDs.
