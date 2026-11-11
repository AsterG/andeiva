# Testes de armazenamento finito

Executar apenas num laboratório autorizado e recuperável Debian 13 AMD64. São
necessários root, `unshare`, ferramentas de montagem e a conta existente `andeiva`
com UID/GID 1000. O harness cria namespaces privados de montagem/rede e três tmpfs
descartáveis de 16 MiB e 256 inodes. Não altera serviços, rede, interfaces, rotas
ou regras do appliance. Nunca encher o filesystem do host para este teste.

Compilar o executável em desenvolvimento a partir do código revisto:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -trimpath -buildvcs=false -o configpoc-storage.test ./internal/configpoc
sha256sum configpoc-storage.test packaging/preview/tests/storage-pressure.sh
```

Transferir ambos os ficheiros por um meio autorizado e verificar os checksums
registados separadamente. Na consola, criar um diretório novo numa árvore protegida de root (por exemplo `/root`)
e instalar o executável com modo 0555 e o harness com modo 0500. Executar com
caminhos absolutos e o SHA-256 verificado do executável:

```sh
bash /CAMINHO/ABSOLUTO/ROOT/storage-pressure.sh --authorized-debian-lab /CAMINHO/ABSOLUTO/ROOT/configpoc-storage.test SHA256_VERIFICADO --isolated-storage-only
```

Resultado esperado: casos bytes, inodes e readonly aprovados, seguidos de
`ANDEIVA_STORAGE_LAB_RESULT=pass`. Bytes e inodes verificam admissão normal,
leituras e recuperação após remover apenas os seus ficheiros de preenchimento.
Readonly verifica a observação real de apenas leitura; não inicia um armazenamento
já montado como apenas leitura. O harness desmonta os tmpfs e remove o diretório
vazio. Se a desmontagem falhar, não eliminar o caminho recursivamente: inspecionar
o namespace indicado e parar o processo de teste antes da limpeza.

Os motores são simulados; não se testa tráfego. O resultado não comprova quotas,
reserva física, resistência a cortes de energia, retenção de auditoria protegida
ou continuidade permanente do dataplane. O espaço observado pode mudar; falhas de
escrita/fsync continuam a exigir recuperação. Esses gates permanecem abertos.
CI partilhado verifica apenas sintaxe, testes unitários e compilação multiplataforma;
não executa estas operações privilegiadas.
