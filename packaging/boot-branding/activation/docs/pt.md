# Ativação local da inicialização — experimental

Somente para o operador de plataforma autorizado no console local. Não é uma API web, instalador ou mecanismo de atualização assinado. Testes com arquivos isolados não comprovam ativação, gráficos ou recuperação nativos. Não executar no Windows.

Construir e testar como usuário normal Linux/WSL com o Go do repositório:

```sh
go test -race ./packaging/boot-branding/activation
go vet ./packaging/boot-branding/activation
go build -trimpath -buildvcs=false -o /tmp/andeiva-boot-activation ./packaging/boot-branding/activation
```

Não adiciona dependências. Os testes substituem comandos apenas no código de testes e nunca executam ferramentas reais de inicialização. O binário real usa raiz `/` e executáveis fixos; não aceita caminhos alternativos ou modo de teste.

Antes da execução: verificar pacote, fechamento de dependências offline, backup independente **anterior** à instalação do Plymouth, snapshot recuperável e recuperação local autorizada ensaiada. Inicializar um kernel alternativo ou provar uma mídia independente; rescue usando apenas o initramfs que será substituído não basta. Somente o layout BIOS/Debian13/ext4 documentado é aceito.

Sequência aprovada no console root autorizado: `andeiva-boot-activation preflight`, `andeiva-boot-activation prepare --recovery-verified`, `andeiva-boot-activation apply`. A opção registra uma declaração do operador, não um teste automático. Consultar `andeiva-boot-activation status`: `pending-reboot` não comprova inicialização correta. Reinício e verificações de rede/serviços são etapas separadas; a ferramenta nunca reinicia.

`andeiva-boot-activation restore` restaura backups íntegros sem alterações ambíguas. Usa os destinos do kernel preparado mesmo a partir do kernel alternativo. Recusa alterações desconhecidas, backup corrompido ou interrupção com bytes não observados; preservar evidências e usar recuperação independente. Não excluir backups ou recursos do tema selecionado. Apenas uma ativação é suportada; não há limpeza automática de backups.

Após uma restauração completa, `prepare --recovery-verified` permite rearmar o mesmo conjunto se ambos os kernels e todos os hashes originais/de contexto/efetivos coincidirem. Não substitui os backups originais. Outro contexto ou qualquer alteração exige recuperação revisada, não a exclusão do journal.

O menu permanece visível por cinco segundos. Não altera `10_linux`; mensagens normais podem permanecer. Não garante A/B, resistência a cortes, reversão completa de pacotes ou branding concluído. Consultar [desenho](../DESIGN.md) e os testes nativos pendentes.

A inicialização normal usa `loglevel=3`: emergências, alertas e mensagens críticas do kernel continuam no console; erros e avisos comuns permanecem no registro para diagnóstico autorizado. Esc mostra os diagnósticos textuais disponíveis; para saída completa do kernel usar uma inicialização temporária sem `quiet`/`loglevel=3` ou com nível de console superior. Não altera argumentos de recuperação, bloqueia drivers, ignora verificações do sistema de arquivos ou desativa registros. Texto de verificação do disco pode aparecer antes do Plymouth; observação nativa ainda é necessária.

A inicialização normal usa `systemd.show_status=error`: oculta linhas de unidades bem-sucedidas e mantém estados de falha e o journal. Verifique o console real após a saída do Plymouth.
