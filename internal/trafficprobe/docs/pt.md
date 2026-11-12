# Testes de tráfego a partir de um cliente autorizado

`andeiva-traffic-probe` é uma ferramenta de desenvolvimento de execução única, sem
privilégios e sem alterar interfaces, rotas, DNS ou firewall. Não é a CLI oficial
de administração. `--authorized-lab` declara o escopo; não autentica o operador nem
comprova que ele controla o destino.

Exige uma IPv4 de origem já atribuída ao cliente e um único destino IPv4/porta.
Vincula e verifica os endereços reais. Não executar no próprio appliance e
apresentar o resultado como tráfego de uma VM atrás do firewall.

- `tcp`: observa uma conexão, sem comprovar uma regra Allow.
- `udp-echo`: exige eco exato do desafio aleatório de 32 bytes. Requer um destino
  de eco autorizado; serviços UDP comuns podem não oferecer esse comportamento.
- `dns-a`: resolução IPv4 bem-sucedida com I/O DNS observada no destino explícito.
  Registra tentativas UDP/TCP e fallback reais. `resolved_with_dns_io` e
  `resolved_ipv4` não atribuem os valores ao servidor: `resolution_source` é sempre
  `unattributed`. NSS pode receber NXDOMAIN e depois resolver pelo hosts local.
  Um seam de teste controlado simula esse fallback após NXDOMAIN loopback real,
  sem alterar hosts/NSS do sistema. Sem I/O DNS retorna `dns_not_observed`, sem
  valores. Limites: 32 IPv4 e 16 tentativas; não comprova respostas A do servidor
  nem DNSSEC.
- `http-head`: conecta somente à IPv4 escolhida e usa o hostname da URL para Host
  e TLS, sem DNS implícito. Sem proxy, redirecionamento, conexão persistente ou
  HTTP/2; cabeçalhos limitados a 16 KiB e corpo não lido.

Timeout máximo: 15 segundos. Timeout, conexão recusada ou falta de eco **não
comprovam Deny**. Correlacionar tuplas/tempo com contadores, ruleset e conexões
traduzidas reais. Sucesso não comprova NAT ou passagem por ANDEIVA. Bytes são dados
tratados pelos sockets deste processo, não contadores por regra ou pacotes da rede.
A hora UTC inicial usa o relógio do cliente, sem comprovar sua confiança; o tempo
decorrido mede esta execução, não a largura de banda da rede.

HTTPS sempre verifica certificado e hostname, com TLS 1.2 ou superior. Usa a
confiança atual do sistema ou `--ca-file` de origem confiável independente. Nunca
confiar automaticamente no primeiro servidor desconhecido. O arquivo deve ser
absoluto, regular, sem links nos ancestrais, sem escrita por grupo/outros, até
1 MiB e 256 certificados PEM válidos. Linux também rejeita substituições por
link/FIFO sem bloquear; outras plataformas precisam de qualificação nativa.

JSON não contém credenciais, desafio, URL/caminho, query ou erros brutos. URLs com
usuário, query ou fragmento são rejeitadas; a porta da URL deve coincidir com a do
destino. Ajuda: `--lang en|es|pt`; chaves/códigos JSON não mudam com o idioma. A
enumeração do sistema, carregamento de certificados e leituras de arquivos não
são interrompíveis por contexto: não há promessa de limite absoluto de tempo/RAM
nessas operações. Não ficam processos nem histórico permanente.

Modelos: substituir marcadores por valores do laboratório autorizado.

```sh
andeiva-traffic-probe --authorized-lab --mode tcp --source-ipv4 IP_CLIENTE --target-ipv4 IP_SERVIDOR --port PORTA
andeiva-traffic-probe --authorized-lab --mode dns-a --source-ipv4 IP_CLIENTE --target-ipv4 IP_DNS --port 53 --dns-name example.net
andeiva-traffic-probe --authorized-lab --mode http-head --source-ipv4 IP_CLIENTE --target-ipv4 IP_WEB --port 443 --url https://example.net/ --timeout 5s
```

Saída 0: observação positiva; 1: observação falha/neutra ou erro de saída; 2:
invocação inválida. Não são códigos Allow/Deny. Não colocar segredos em argumentos.

No repositório: `go test -race ./internal/trafficprobe ./cmd/andeiva-traffic-probe`
e `go vet ./internal/trafficprobe ./cmd/andeiva-traffic-probe`. Testes usam somente
listeners temporários loopback, DNS controlado e certificados de teste; não
comprovam Internet, NAT ou routing real.

Arquivos CA personalizados são aceitos apenas no Linux. Outros sistemas rejeitam `--ca-file` antes de acessar o filesystem com `invalid_ca_file`; HTTPS com confiança do sistema mantém a verificação dos certificados. Outro sistema exige abertura segura e testes nativos.
