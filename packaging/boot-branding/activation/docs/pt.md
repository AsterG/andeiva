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

## Verificações portáveis e diagnóstico temporário

A elegibilidade usa a topologia real das montagens e o tamanho de bloco do sistema de arquivos, sem depender do nome do disco ou hipervisor. Testes do parser não comprovam qualificação nativa do Proxmox, servidores físicos ou firmware não testado.

Somente o operador de plataforma autorizado pode usar `andeiva-boot-activation apply --diagnostic-boot`, após restaurar e preparar com nova confirmação de recuperação. Envia o fluxo para `/dev/null` e preserva um buffer limitado, potencialmente sensível, em `/run/andeiva-boot-plymouth-debug.log` quando o Plymouth termina. Não introduza credenciais nas perguntas do Plymouth durante este teste de laboratório. Configurações debug anteriores e arquivo de log preexistente são recusados. A verificação de capacidade não reserva espaço após reiniciar.

Após a saída do Plymouth, confirme que o caminho fixo é um arquivo regular de root, modo 0600 e menor que 1 MiB antes da coleta privada. Nunca publique traces brutos no Git, CI, administração comum ou pacotes de suporte. A coleta pode ser incompleta; outro reinício pode substituí-la. Não altera drivers, conectores, resolução, firmware ou argumentos de recuperação.

O diagnóstico permanece selecionado até executar `restore`, `prepare --recovery-verified`, `apply` normal e reiniciar normalmente. Trocar de modo com configuração pendente é recusado; repetir o mesmo apply é idempotente. Colete primeiro o trace e retire o diagnóstico antes de devolver o appliance ao uso normal.

## Compatibilidade gráfica opcional

Para uma falha observada na apresentação DRM, após verificar a recuperação, execute `restore`, `prepare --recovery-verified` e `apply --redraw-compatibility`. Este modo explícito acrescenta o argumento padrão de redesenho do Plymouth apenas à inicialização normal. Não força uma resolução nem altera drivers; o modo padrão permanece igual. Não pode ser combinado com a inicialização de diagnóstico.

Verifique uma reinicialização real, o logotipo e os textos completos, os diagnósticos com Esc, a saúde do serviço e o consumo de CPU/RAM. As redefinições mais frequentes da imagem podem aumentar o trabalho gráfico; uma prévia isolada não valida a plataforma. Para remover a opção, restaure, prepare novamente, execute `apply` sem opções e reinicie. Não se afirma compatibilidade universal.
## Instalação offline pendente

Se ocorrer `ANDEIVA_BOOT_OFFLINE_INSTALL_PENDING`, não repita a ativação ou restauração nem apague o marcador apenas porque um PID ou bloqueio desapareceu. Uma instalação interrompida pode deixar processos de pacotes ativos. As consultas `status` e `capabilities` para root continuam disponíveis. A recuperação local autorizada deve inspecionar o diário e os backups do instalador e comprovar que o processamento de pacotes terminou antes de resolver a condição pendente. Não há rollback automático de pacotes nem garantia contra falhas de energia.