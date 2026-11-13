# Reserva física de recuperação

Primitiva interna com 1–32 arquivos fixos e dois bancos alinhados, pré-alocados
e com checksum. Cada banco comporta 4 KiB–1 MiB. Exige `fallocate` Linux, recusa
arquivos esparsos e verifica proprietário, permissões, dispositivo, inode e
bloqueio exclusivo do diretório privado recebido por descritor.

`Claim` atribui espaço a uma operação. `Write` verifica a concessão, grava o banco
inativo e sincroniza dados e cabeçalho. Resultados incertos bloqueiam novas
gravações pelo handle. Essas operações não criam arquivos nem reciclam reservas
por idade. Configuração, auditoria e rede existentes permanecem inalteradas.

O coordenador deverá persistir o `Binding` exato junto à intenção durável.
Somente `ReadBound` verifica pool, posição, proprietário, sequência e digest.
`Read(owner)` pode recuperar um banco anterior; não comprova uma transação
concluída. Um primeiro Claim corrompido não libera espaço. Checksums detectam
corrupção; não são assinaturas nem proteção contra o proprietário malicioso.

## Reprodução

```sh
go test -race ./internal/recoveryreserve -count=3
go vet ./internal/recoveryreserve
GOOS=linux GOARCH=amd64 go test -c ./internal/recoveryreserve -o reserve.test
sha256sum reserve.test
```

Em Debian 13 de laboratório, com console e snapshot recuperável, copie o binário
e repositório. Instale o binário em diretório privado pertencente a root e execute
como root:

```sh
bash packaging/preview/tests/recovery-reserve-pressure.sh \
  --qualify-isolated-ext4 /caminho/absoluto/root/reserve.test SHA256 andeiva
```

Substitua SHA256 pelo digest hexadecimal verificado e `andeiva` por uma conta
não privilegiada existente cujo grupo principal tenha o mesmo nome. O script usa
namespaces privados de montagem/rede e uma nova imagem ext4 de 64 MiB. Verifica
esgotamento de blocos/inodes e leitura exata após reabertura, desmonta a imagem
e preserva o diretório de evidência. Não executa testes privilegiados no CI.

Ainda faltam integração do coordenador, isolamento por quotas, RO/EIO/EDQUOT,
retirada autorizada e continuidade do tráfego. Pré-alocação e testes ext4 não
garantem capacidade de metadados/journal/COW em todos os dispositivos. Saídas de
processo não comprovam resistência a cortes de energia.
Os testes Debian13 passaram esgotamento real de blocos/inodes em ext4 isolado64MiB, UID1000 sem capacidades. Binding/reabertura0,62s; CPU de preparação/teste0,414153s/pico cgroup74.477.568B incluem formatador e cache. Regressão nativa separada: CPU0,049284s/pico16.248.832B. São medições do fixture; não RSS do serviço, garantia universal nem continuidade integral do appliance.

As leituras compartilhadas mantêm identidades separadas: `ReaderAccessV2.ReadFile` exige o grupo exclusivo do helper; `ReadOwnedFile` exige o proprietário exato não root. Ambas verificam limites, diretório fixado, UID/GID, permissões, ACL e ausência de links. A API não ingressa no grupo leitor. Essas funções não concedem bloqueio de escrita nem autoridade para aplicar políticas.
