# Bundle experimental de inicialização offline

Apenas para desenvolvimento interno autorizado. Não é uma atualização assinada, release, instalador A/B ou autorização para redistribuir dependências. O checksum detecta alterações; obtenha o bundle e o checksum esperado por um canal confiável independente. Nunca execute um instalador não confiável como root.

## Compilação

Use um ambiente Debian 13 AMD64 de desenvolvimento sem root, com APT, chaveiro Debian, sqv, dpkg, Go conforme `go.mod`, GNU tar/coreutils, gzip e util-linux. Somente esta etapa acessa os repositórios oficiais Debian fixados. As verificações de assinatura, data, validade e HTTPS permanecem habilitadas.

```sh
bash packaging/boot-branding/offline/build.sh \
  /private/target-dpkg-status /private/reviewed-product-debs \
  /private/bundle-output 1794355200
```

O diretório deve conter exatamente os pacotes revisados `andeiva-boot-branding` e `andeiva-boot-activation`, na mesma versão experimental. O ativador deve declarar proteção offline versão 1. O estado dpkg privado influencia a resolução, mas não entra no bundle. Preserve-o privadamente para repetir a compilação. Reprodutibilidade byte a byte exige os mesmos pacotes e metadados assinados; os repositórios podem mudar entre execuções.

Antes de resolver ou instalar, devem estar configurados `grub-common`, `grub2-common`, `grub-pc` e `grub-pc-bin` versão `2.12-9+deb13u2` (amd64), além de `initramfs-tools` e `initramfs-tools-core` versão `0.148.4` (all). Este bundle não pode instalá-los nem atualizá-los. Apenas subconjuntos de 26 tuplas de dependências revisadas e compiladas são aceitos; uma assinatura válida não autoriza versão/hash diferente. Atualizações de segurança exigem seu procedimento qualificado; não contorne essa proteção nem a interprete como congelamento indefinido.

## Inspeção e instalação

O escopo atual admite Debian 13 AMD64, BIOS e uma raiz ext4 contendo `/boot`, `/etc`, `/usr` e `/var/backups`, sem arquiteturas dpkg adicionais. Outros layouts são recusados. Isso não qualifica todos os equipamentos ou hipervisores. Antes de instalar, exija espaço suficiente, dpkg íntegro, dois kernels completos e recuperação independente já ensaiada. Não instala kernels nem transforma Debian existente em A/B.

Verifique o checksum esperado antes de extrair. Extraia apenas um bundle confiável em diretório controlado e revise-o antes de colocá-lo, pertencente a root e sem escrita para outros, em `/var/lib/andeiva-boot-bundles/INVENTORY_SHA256`. A compilação mostra esse identificador. Não acrescente estado privado, credenciais ou evidências de diagnóstico.

```sh
cd /var/lib/andeiva-boot-bundles/INVENTORY_SHA256
./install.sh inspect
./install.sh install --recovery-verified
```

`inspect` verifica assinaturas, hashes, inventário e simulação APT offline; remove seu staging temporário. `install` repete a validação, exige confirmação da recuperação e faz backup de boot/configuração antes de APT num namespace de montagem privado. Somente esse namespace recebe `update_initramfs=no` por bind somente leitura. Não carrega fontes, preferências ou hooks APT do host. Não executa APT online, upgrades, remoções, ativação do tema ou reinício. Versões instaladas devem coincidir. O ativador existente deve informar `offline_install_guard: 1`; versões antigas exigem atualização revisada separadamente.

O sucesso verifica versões, capacidade de proteção, hashes de boot, inventário de kernels e política initramfs original antes de remover o marcador persistente. Repetir a instalação concluída retorna `ANDEIVA_OFFLINE_ALREADY_INSTALLED`. A ativação do branding continua sendo uma operação separada, com seus próprios requisitos de recuperação.

O identificador vincula todos os arquivos, incluindo instalador e verificador: é SHA-256 do arquivo canônico `SHA256SUMS`. IDs antigos baseados apenas nos pacotes não são aceitos. Os logs combinam stdout/stderr, ocupam no máximo 4 MiB e indicam truncamento explicitamente. A saída restante continua sendo lida mesmo após falha de escrita. O timeout cobre produtor e logger, incluindo filhos que mantêm o pipe aberto. Truncamento, erro de escrita ou falha de qualquer processo mantém o estado pendente mesmo se APT instalar todos os pacotes.

Somente o log terminal duplicado do APT é redirecionado para `/dev/null`; permanecem o log principal limitado, histórico APT e auditoria de ações dpkg. Outros logs do sistema, histórico/planner e scripts de pacotes não estão automaticamente cobertos pelos 4 MiB: exigem política de armazenamento e validação nativa. Cópias de cache usam nomes canônicos APT e hash verificado, incluindo `%3a` minúsculo para epochs, sem habilitar downloads.

## Falhas e recuperação

Uma interrupção após a criação do marcador mantém `/var/backups/andeiva-boot-offline/install-pending` e os backups privados. Instalação e ativação devem recusar esse estado incerto, mesmo quando todos os pacotes parecem instalados. Um filho APT pode sobreviver ao instalador; ausência do processo pai não comprova término.

Este incremento não fornece rollback de pacotes, retomada ou comando para remover o marcador. Não o exclua nem execute reparação APT genérica para contornar a proteção. A recuperação autorizada deve confirmar que APT/dpkg e seus filhos terminaram, verificar backups e estado real de boot/configuração/pacotes, e usar um procedimento revisado ou snapshot/backup independente previamente ensaiado. Mantenha as evidências privadas. Desinstalar o produto ou apagar o marcador não desfaz scripts Debian.

## Limites de validação

```sh
go test -race ./packaging/boot-branding/offline/check
go vet ./packaging/boot-branding/offline/check
bash -n packaging/boot-branding/offline/*.sh
```

Fixtures e sintaxe não provam isolamento real, recuperação após interrupção, instalação limpa ou consumo nativo. Exigem evidência e revisão independente. O bundle não acrescenta processos permanentes; CPU, memória, tempo e disco da instalação ainda precisam ser medidos no destino.

A âncora de confiança Debian existente deve ser o arquivo regular `/usr/share/keyrings/debian-archive-keyring.pgp`, pertencente a root e sem escrita para grupo ou outros, com diretórios ascendentes seguros. O alias simbólico convencional `.gpg` não é usado; outros caminhos ou links de chaveiros não são aceitos.
