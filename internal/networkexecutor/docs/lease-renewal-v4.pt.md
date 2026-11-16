# Atualização da evidência operacional do lease

Exige snapshots canônicos com sequência nova e a mesma identidade, proprietário,
interface, configuração e delta L3 completo. Somente sequência, prazo absoluto e
hash podem mudar. Aceita prazo novo menor; nunca fabrica uma validade mínima.

A montagem confiável autentica Work e comprova forwarding e gate fechados.
O executor verifica propriedade original, baseline, evidência atual e estado
físico antes e depois. Atualiza somente evidência em memória; não escreve
endereços, rotas, snapshot selecionado ou R2.

Somente o erro de renovação classificado permite fechar e usar evidência fresca.
Outros erros de autoridade mantêm o fence irreversível. O preflight do gate fechado
rejeita sequências consumidas sem efeitos e nunca abre tráfego.

Reproduzir: `go test -race ./internal/networkexecutor` e
`go vet ./internal/networkexecutor`. Inclui delta imutável, replay, falhas de
readback, cancelamento, lifetime encerrado, fence e descarte. Não adiciona processos
ou trabalho periódico. Não ativa renovação ou qualifica tráfego ou recursos do
appliance sozinho.
