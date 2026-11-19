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
O registro rejeita o ID 4294967295, reservado pelo Kea.

Um flock independente do diretório serializa as chamadas. A publicação
sincroniza o marcador `scope-bindings.v1.pending` e o diretório antes de preparar
`scope-bindings.v1.publish`. Ambos os arquivos são criados de forma exclusiva
sem seguir links. O candidato é sincronizado e renomeado de forma atômica. O
marcador só é removido depois de sincronizar o diretório após o rename. Um
marcador ou candidato restante bloqueia todas as chamadas. Se a sincronização
da remoção falhar, a tentativa termina com erro e sem IDs. O manifesto já foi
sincronizado e, se o marcador reaparecer após reiniciar, continua bloqueando
chamadas. O registro mantém o serviço que já estava ativo. A E/S de disco pode
atrasar o cancelamento.

O primeiro ID exige um diretório de leases vazio e bloqueado, inclusive quando
já existe um manifesto com zero entradas. No limite, as consultas existentes
continuam sem escritas e as novas alocações falham.

Para recuperar, pare o motor e todos os escritores durante manutenção
autorizada. Preserve juntos os arquivos do registro e o diretório de leases
como evidência do incidente. Verifique o armazenamento, o histórico completo
das atribuições e a concordância com os leases preservados. Sincronize o
manifesto verificado e seu diretório antes de remover o marcador ou o
candidato. Sincronize o diretório novamente depois. Se faltarem evidências,
mantenha o bloqueio. Preserve todas as concessões. O rollback de configuração
nunca deve restaurar o manifesto separado de seu histórico de leases. Detectar
uma restauração arbitrária por root exige uma âncora monotônica externa.

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
