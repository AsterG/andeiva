# Qualificação do plano de rede tipado

O laboratório Debian 13 existente de três namespaces aplica os dois endereços
IPv4 estáticos e a rota padrão do gateway por `internal/networkexecutor`.
Verifica o namespace próprio, abre e confere o inode da montagem, e entrega um
descritor confiável e uma vida de recuperação independente do supervisor.
Veth, MAC, estado dos enlaces, rotas dos pares e IPv6 continuam como preparação
do fixture. Mantém testes TCP/UDP, SNAT, negação, revogação, IPv6 e conntrack
observado opcional. Nenhum namespace adicional é criado.

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

Integração preparada para revisão, sem qualificação privilegiada comprovada.
Testes sem privilégios:

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
Alpha. Medições CPU/RAM pendentes.
