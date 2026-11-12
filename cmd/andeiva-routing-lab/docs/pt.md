# Qualificação do plano de rede tipado

O laboratório Debian 13 existente de três namespaces aplica os dois endereços
IPv4 estáticos e a rota padrão do gateway por `internal/networkexecutor`.
Verifica o namespace próprio, abre e confere o inode da montagem, e entrega um
descritor confiável e uma vida de recuperação independente do supervisor.
Veth, MAC, estado dos enlaces, rotas dos pares e IPv6 continuam como preparação
do fixture. Mantém testes TCP/UDP, SNAT, negação, revogação, IPv6 e conntrack
observado opcional. Nenhum namespace adicional é criado.

A unidade do laboratório de root com capacidades mínimas aceita somente o opt-in
literal `ANDEIVA_LAB_HOST_ANCHOR_FD=0`. O gestor fornece FD 0 por
`StandardInput=file:/proc/1/ns/net` antes de reduzir privilégios; o runner usa
`NewWithHost` com `os.Stdin`. Outros números ou caminhos são rejeitados. Sem opt-in
mantém `New` e o controle de PID 1. Não adiciona SYS_PTRACE, aceita identidades de
host do chamador ou reduz controles. Erros identificam constructor, apply e verify
com etapas do laboratório em inglês.

Trecho testado para um harness do laboratório de root e revisado, não uma unidade
completa; o supervisor permanece no namespace de rede do host:

```ini
[Service]
StandardInput=file:/proc/1/ns/net
Environment=ANDEIVA_LAB_HOST_ANCHOR_FD=0
```

O modo de fluxos exige `nf_conntrack_netlink` carregado antes de iniciar.
Verificar `test -d /sys/module/nf_conntrack_netlink`. Se ausente, somente o
supervisor root explicitamente autorizado pode executar
`sudo modprobe nf_conntrack_netlink` como requisito do laboratório. O helper não
carrega módulos nem recebe SYS_MODULE; não adicionar SYS_PTRACE para acessar
PID 1. O runner não instala pacotes.

`Apply` e `Verify` devem passar antes do tráfego. Ao sair: parar processos filhos,
`Restore` com verificação do snapshot IPv4 controlado, `Close` e por último limpar
namespaces próprios. A restauração mantém a vida do supervisor mesmo quando a
solicitação do laboratório expira. Falhas de limpeza fazem a execução falhar.

Marcadores emitidos somente após cada operação terminar corretamente:

```text
PASS typed network plan applied/readback
PASS typed network plan applied/readback/restored
PASS namespaces cleaned; host routes and nftables unchanged
```

Fonte `460fece`, prefixo SHA-256 do binário `590a4005`: qualificação nativa
Debian 13 amd64 PASS com somente SYS_ADMIN/NET_ADMIN e FD 0 do host fornecido.
Passaram plano tipado, TCP/UDP SNAT, conntrack real, ICMP relacionado, negação
IPv6/reversa, revogação TCP, routing sem NAT, limite de autorização do NAT,
limpeza e invariantes externos do host. Revisões de root e arquitetura sem achados
críticos/altos/moderados. Tempo 4.408428 s, CPU 1.116154 s, pico 32,321,536 bytes:
uma execução do fixture, não benchmark do appliance.

Antes de reproduzir, testes sem privilégios:

```sh
go test -race ./internal/networkexecutor ./cmd/andeiva-routing-lab ./internal/routednft
go vet ./internal/networkexecutor ./cmd/andeiva-routing-lab
go build -trimpath -o /tmp/andeiva-routing-lab ./cmd/andeiva-routing-lab
```

Somente após revisão do código e autorização explícita do laboratório isolado,
na VM Debian 13 amd64 descartável com snapshot de recuperação e ferramentas
necessárias já instaladas:

```sh
sudo /tmp/andeiva-routing-lab --run-isolated-lab-with-flows
```

Nunca executar em appliance de cliente nem alterar redes Windows/VPN.
Exige IPv4 inicialmente vazio; migração da LAN administrativa, DHCP e recuperação
durável não são suportados. O estado de recuperação permanece em memória.
Não altera routing, NAT, firewall ou sysctls do host. Não comprova produção,
inspeção obrigatória, integração Docker/EKS ou conclusão de Firewall & Routing
Alpha. Contêineres e orçamento de recursos do appliance não qualificados.
