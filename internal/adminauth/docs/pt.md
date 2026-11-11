# Admissão de acesso administrativo

Escopo experimental: credenciais aleatórias provisionadas da administração isolada.
[English](../README.md) · [Español](es.md).

HTTP e SSH usam o IP do socket receptor, ignorando cabeçalhos de forwarding.
IPv4-mapped é normalizado; origens ausentes, inválidas, com zona, não especificadas
ou multicast são rejeitadas. Delegação de origem por reverse proxy não é implementada.

Falhas anônimas compartilham uma cota global de quatro admissões por segundo e outra
por origem. A tabela fixa mantém até 128 origens, com expiração preguiçosa de um minuto.
Rejeições não prolongam retenção nem expulsam entradas ativas. Credenciais válidas
usam outra cota de quatro por segundo e independem dessa tabela, mesmo cheia ou atrás
do mesmo NAT. Permanecem as 32 sessões, expiração, CSRF, RBAC e auditoria obrigatória.
Cada tentativa do método interno `Login` compartilha a cota anônima; credenciais
válidas também consomem a cota verificada global. Credenciais inválidas nunca a
consomem. Assim essa entrada compatível não cria outra cota verificada. HTTP e SSH
usam `LoginFrom`.

A classificação limita usuário a 64 bytes e credencial a 64 caracteres: são 32 bytes
aleatórios, não senhas escolhidas pelo usuário. Não reutilizar esse armazenamento
como algoritmo de hashing de senhas. Segredos não são registrados.

Os limites são locais ao processo e reiniciam com ele. Não limitam todos os handshakes
nem garantem disponibilidade contra qualquer ataque. O empréstimo de sessões HTTPS
pelo SSH mantém sua rota anterior. Auditoria cheia continua sendo bloqueio separado:
falha na persistência obrigatória fecha a autenticação. Não há rotação, agregação,
exclusão, mudança de formato persistido ou novas regras de tráfego.

## Testes reproduzíveis

```sh
go test -race -count=1 ./internal/adminauth ./internal/adminapi ./internal/localssh
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
go test -race -count=10 ./internal/adminapi -run '^TestLoginOriginFloodCannotBlockVerifiedHTTPS$'
```

O último teste requer Linux, usa TCP real de `127.0.0.2/3` e TLS com certificado
verificado, sem root nem alterações de rede. Falhas podem retornar 401/429 conforme
a janela real; cotas exatas usam relógio controlado. Também se verificam IPv4/IPv6,
tabela cheia, NAT compartilhado, cabeçalhos falsos, concorrência, sessões, auditoria
e transporte SSH. Backend e destino de auditoria são fixtures; não se aplica nftables
nem se modifica o appliance instalado.

A estrutura fixa mede 7.232 bytes no Linux AMD64 testado; não é RSS nem garantia de
desempenho. Microbenchmarks excluem transporte e persistência de auditoria.
Recuperação com armazenamento cheio continua pendente.
