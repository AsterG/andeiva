# Montagem administrativa roteada sem capacidades

`OpenRoutedOperationsRuntimeV3` é uma fábrica Linux para o supervisor, não uma
operação HTTP ou opção de instalação. Consome dois sockets Unix herdados distintos
e os PIDs dos helpers autenticados pelo supervisor. O lançamento verifica sua
origem; nenhuma solicitação escolhe caminhos ou identidades.

A API exige UID/GID exatos, capacidades vazias e `NoNewPrivs` no namespace do host.
São obrigatórios o perfil compartilhado fixado, três pools previamente abertos e
prazos absolutos. O handshake v3 exclui o controlador anterior antes do handshake
v2 de compatibilidade, Snapshot/Attach ou abertura do escritor. Ambos os canais
são necessários; não há negociação, repetição automática ou fallback. A autoridade
remota fica vinculada aos metadados confiáveis; uma autoridade fornecida pelo
chamador é rejeitada. As verificações canônicas continuam no coordenador.

O lançamento agrupado deve criar o servidor de compatibilidade com
`NewRoutedCompatibilitySessionV2`. Permite apenas consultar estado, vincular a
observação e lê-la durante toda sua vida, inclusive após reconexão. Rejeita todas
as mutações antes do guardião anterior. Os efeitos agrupados usam autorização
do estado selecionado v3; um helper anterior irrestrito não é aceito.
O handshake v2 sozinho não comprova essa política de lançamento.

Os sockets são transferidos na entrada e fechados em falhas. Roots, pools e motores
locais continuam pertencendo ao chamador. Fechar a administração libera escritor
e canais; não remove regras, namespaces, listeners ou o guardião independente.

Os testes usam sockets Unix e credenciais reais com motores simulados: ordem dos
handshakes, rejeição de identidade/perfil sem gravar armazenamento e preservação
da política ao fechar. Não qualificam montagem completa com armazenamento
compartilhado, tráfego, instalação ou reinicialização do SO.

Linux: `go test -race ./internal/previewruntime -run TestRoutedAPIV3 -count=1`.
A fábrica não ativa serviços implantados.

As verificações prévias de metadados e perfil do diretório compartilhado apenas
leem identidade antes do handshake: não abrem escritor, bloqueio ou fazem gravações.
PIDs distintos exigem valores fixados pelo lançamento confiável. Esta fábrica
não implementa esse lançamento ou provisionamento do supervisor.
