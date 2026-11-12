# Volumes inativos de armazenamento para laboratório

Este componente de desenvolvimento prepara quatro imagens ext4 **inativas**.
Não monta, ativa, migra ou remove dados; não adiciona serviços, listeners ou
trabalhos periódicos. Não encerra AND-01/AND-02 nem comprova continuidade de
tráfego com armazenamento cheio. `andeiva` continua sendo a CLI administrativa
oficial; `andeiva-storage-lab` é uma ferramenta local de desenvolvimento só de root.

## Perfil fixo de testes

| Domínio | Capacidade da imagem | Inodes solicitados |
| --- | ---: | ---: |
| Configuração | 128 MiB | 8192 |
| Auditoria protegida | 128 MiB | 4096 |
| Observações | 64 MiB | 1024 |
| Recuperação | 64 MiB | 2048 |

Total: 384 MiB. Metadados e journals consomem parte de cada imagem; não são bytes
livres utilizáveis nem dimensionamento de produto aprovado. A preparação exige
mais 64 MiB e 64 inodes observados no sistema de arquivos externo. Isso é
admissão, não quota ou proteção contra gravações externas concorrentes.

A alocação de blocos por fallocate é obrigatória, sem alternativa sparse/truncate.
O formatador recebe somente o descritor herdado 3 do novo arquivo regular criado
exclusivamente, nunca um caminho ou dispositivo fornecido pelo operador. Executa
`/usr/sbin/mke2fs` com argumentos/ambiente fixos, um único `-F` e
`nodiscard,lazy_itable_init=0,lazy_journal_init=0`. Proprietário, permissões e
ancestrais são verificados; a procedência do pacote exige validação independente.
Após o formato, leitura/gravação limitada preserva cada byte e materializa faixas
reservadas; sincronização e verificação abrangem identidade, tamanho, links,
blocos, assinatura e SHA-256. O manifesto é publicado sem substituir destinos.

A alocação é a visível no ext4 externo, não prova de capacidade física sob thin
provisioning, snapshots ou falha da mídia. Não protege contra root malicioso ou
comprova resistência a cortes de energia. Montagens privadas e integração aos
serviços reais continuam como testes independentes. Consulte o
[manual do mke2fs](https://man7.org/linux/man-pages/man8/mke2fs.8.html).

## Compilação e execução

Use a versão Go fixada pelo repositório, sem root:

```sh
go test -race ./internal/storagevol ./cmd/andeiva-storage-lab
go vet ./internal/storagevol ./cmd/andeiva-storage-lab
go build -trimpath -buildvcs=false -o /tmp/andeiva-storage-lab ./cmd/andeiva-storage-lab
sha256sum /tmp/andeiva-storage-lab
```

Transfira somente o binário revisado e compare o checksum guardado por uma origem
confiável independente. A preparação nativa exige UID/GID root 0, Debian 13 AMD64
e um sistema externo ext4. Não instala pacotes ou altera flags do filesystem.
O indicador registra intenção; não autentica ou prova posse do laboratório.
Com laboratório autorizado e recuperável:

```sh
andeiva-storage-lab --authorized-debian-lab --operation plan
andeiva-storage-lab --authorized-debian-lab --operation prepare
andeiva-storage-lab --authorized-debian-lab --operation inspect --id PREPARED_ID
```

`PREPARED_ID` é o identificador hexadecimal minúsculo de 32 caracteres devolvido
por `prepare`. A base fixa é `/var/lib/andeiva-storage-lab`; não há caminhos ou
tamanhos alternativos. Uma preparação existente, mesmo incompleta, bloqueia outra.
Arquivos desconhecidos, links, proprietários/permissões incorretos e manifestos
inválidos são recusados sem remoção. Ajuda: `--lang pt --help`.

Falhas mantêm a área parcial. Publicação ambígua retorna
`ANDEIVA_STORAGE_VOLUME_UNCERTAIN`. Inspeção somente leitura pode verificar uma
preparação completa após interrupção do processo, mas não redefine hashes de
imagens alteradas por montagem/gravação posterior.

## Testes nativos e limpeza

O coordenador usa o harness existente
`packaging/preview/tests/storage-pressure.sh`, com namespaces privados de montagem
e rede. Não monte imagens em runners compartilhados nem duplique o harness.
Ainda é necessário provar identidades/orçamentos independentes, encher observações
por bytes/inodes e manter o espaço de configuração/recuperação. ENOSPC, EROFS,
EDQUOT e continuidade do dataplane são gates separados.

Não existe comando de remoção. Antes de limpar explicitamente o conjunto próprio
e inativo, o operador autorizado precisa verificar que todas as imagens estejam
desmontadas e desconectadas, guardando a evidência. Não remover recursivamente
caminhos arbitrários ou usar este procedimento em configuração/auditoria ativa.
Interfaces, rotas, boot e serviços do appliance permanecem intactos.

Os testes unitários usam alocação real de arquivos e **assinatura simulada do
formatador**, não imagens ext4 montáveis. Cobrem colisões de publicação, saídas
reais de processos, substituições, links/FIFO, permissões, manifestos inválidos e
preservação de arquivos alheios. Formato real, montagens e recursos nativos seguem
pendentes até execução documentada. O benchmark mede uma fixture de assinatura de
16 MiB, não formato nativo ou capacidade sustentada:

```sh
go test ./internal/storagevol -run '^$' -bench '^BenchmarkInactivePreparation$' -benchtime=3x -benchmem
```
## Seleção e ameaças

Quotas de projeto podem limitar diretórios, mas dependem do suporte e da
contabilidade correta do filesystem existente; não criam reservas independentes
de inodes nem impedem gravações externas de root. Este teste prepara arquivos de
tamanho fixo para filesystems ext4 separados, com orçamentos independentes de
bytes e inodes quando montados pelo harness autorizado. Não reparticiona nem
remonta a raiz. O projeto de produção ainda exige posicionamento dos volumes,
reservas, retenção da auditoria protegida e testes do armazenamento inferior.
São verificados caminhos externos, links, preparação concorrente, arquivos
parciais e publicação incerta; root malicioso fica fora do modelo.

## Teste nativo opcional com cópias

O mesmo harness oferece um modo opt-in adicional; o modo tmpfs de quatro
argumentos permanece inalterado. Compilar sem root:

```sh
CGO_ENABLED=0 go test -c -o /tmp/storagevol.test ./internal/storagevol
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /tmp/andeiva-storage-lab ./cmd/andeiva-storage-lab
sha256sum /tmp/storagevol.test /tmp/andeiva-storage-lab
```

Transferir binários e harness revisados para diretório de root com ancestrais
não graváveis por terceiros e verificar hashes. No Debian autorizado, como root:

```sh
bash /root/storage-pressure.sh --authorized-debian-volumes \
  /root/storagevol.test RUNNER_SHA256 --isolated-storage-only \
  /root/andeiva-storage-lab INSPECTOR_SHA256 PREPARED_ID
```

Substituir os marcadores por valores verificados. `harness-plan` é uma saída
somente leitura com campos fixos de `inspect`, sem caminhos arbitrários. O
harness verifica originais e copia 384 MiB sem reflinks nem arquivos sparse.
Somente monta cópias em namespaces privados de montagem/rede. Exige 512 MiB livres
antes da cópia; originais e cópias ocupam 768 MiB mais executáveis/metadados.
A base fixa é `/var/lib/andeiva-storage-pressure`; resíduos bloqueiam outro ciclo.

Verifica ENOSPC por bytes e inodes, EROFS e liberação de arquivo removido ainda
aberto após fechar. Blocos/inodes livres de configuração, auditoria e recuperação
devem permanecer iguais durante cada pressão; configuração e recuperação devem
aceitar gravação/fsync. Não demonstra continuidade do appliance. Desmonta e
separa loops antes de remover apenas cópias próprias; falhas de limpeza preservam
o workspace para recuperação autorizada. Não força desmontagens nem remove
originais ou auditoria protegida. O resultado Debian deve ser registrado à parte;
testes normais/CI ignoram este teste e nunca realizam montagens.

O harness rejeita runners/inspetores maiores que 32 MiB e scripts maiores que
128 KiB antes de calcular hashes/copiar. Captura logs limitados exclusivos de root
e exige RUN/PASS reais; casos nativos também exigem marcador exato após todas as
verificações. Exit0 sem testes é falha. Falhas preservam cópias já separadas dos
loops e logs para recuperação autorizada e bloqueiam outro ciclo. Sucesso remove
suas próprias cópias e logs. Regressão sem root/montagens:

```sh
bash packaging/preview/tests/storage-pressure-log-test.sh
```
