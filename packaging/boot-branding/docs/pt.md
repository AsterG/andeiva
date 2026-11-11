# Identidade de inicialização: guia operacional

Este pacote experimental contém recursos gráficos inativos. Não instala Plymouth, seleciona temas, regenera GRUB/initramfs, renomeia entradas nem altera serviços de rede. Uma verificação correta do pacote não demonstra uma inicialização correta.

## Inspeção e validação

Executar `bash packaging/boot-branding/tests/run.sh` a partir do código-fonte como usuário normal Linux/WSL. Os comandos de construção e inspeção estão no [README](../README.md). Os testes não instalam nada nem exigem root. Conservar a procedência offline assinada e os checksums; um checksum não é uma assinatura.

Antes de qualquer ativação futura: verificar acesso autorizado de recuperação pelo console VMware/local, snapshot recuperável, backup da inicialização, espaço/inodes livres e kernel/initramfs anterior intacto. Ensaiar primeiro a recuperação. Instalar dependências do Plymouth pode regenerar initramfs e exige as mesmas verificações. Não alterar Secure Boot, partições, interfaces, rotas ou regras de firewall por motivos visuais.

## Apresentação e diagnóstico

O logotipo original permanece intacto. Os textos próprios do tema são sempre ingleses: `Starting system...`, `Restarting...` e `Shutting down...`. A barra indica atividade, sem porcentagem ou afirmação de saúde correta. O idioma e tema web não selecionam o tema de inicialização. Erros e solicitações de senha externos são preservados; não é possível garantir ocultar firmware ou falhas anteriores ao splash.

Esc, diagnóstico textual, mensagens longas, solicitações de criptografia e ausência de gráficos exigem testes reais de console. Este pacote não adiciona reinicialização Web/CLI. Não criar um endpoint de shell para simular essa integração.

## Atualização, remoção e recuperação

Este incremento não implementa ativação nem sua reversão. Não selecionar manualmente os recursos antes de aprovar o procedimento com recuperação. O pacote inativo altera apenas seus recursos em `/usr/share`. Após uma ativação futura, restaurar e verificar o tema/configuração de inicialização anterior antes de remover recursos referenciados por GRUB ou initramfs. Não excluir kernels de recuperação nem substituir arquivos gerados.

Consultar [desenho e verificações pendentes](../DESIGN.md). Renderização nativa, inicialização/reinício/desligamento, atualização do kernel, restauração e medições ativas continuam pendentes. A reversão de pacotes no Debian existente não equivale à recuperação A/B.
