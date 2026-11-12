# Reservas de recuperação transacional

O caminho v2 é interno e ainda não está habilitado no runtime administrativo
instalado. Não ativa interfaces, encaminhamento ou NAT.

O armazenamento v2 selecionado continua sendo a única autoridade. A montagem
confiável abre três pools distintos: admissão de 4096 bytes, plano de 16384 e
emergência de 8192. Cada pool possui 18 posições: oito comuns, oito para fechar
confirmações e duas do sistema. O solicitante não escolhe caminhos ou posições.

A admissão vincula operação, identidade durável, domínio, gerações e impressão
da solicitação. O intent selecionado e o plano verificado precedem a aplicação.
Emergency registra incerteza; não confirma nem publica Running. Recursos ausentes
ou incertos bloqueiam novas escritas. O helper mantém o prazo independente de
reversão.

O arquivo canônico preserva bytes exatos, conclusão e auditoria: 56 KiB de payload
e 64 KiB para o objeto completo. O índice identifica Lineage+Owner; cada consulta
também verifica Claim ou Binding completo. Escrow não utilizado não inventa uma
operação ou binding. Reutilizar uma posição exige o mesmo arquivo nas duas raízes
selecionadas e CAS exato de identidade, época e bancos. A auditoria protegida é
mantida; reservas desconhecidas não são apagadas.

Reservas lógicas não são RAM, créditos comerciais, quotas de disco ou prova de
espaço físico. Não aumentam o orçamento configurado. O ciclo comum completo deve
caber em 16 MiB/64 inodes, incluindo arquivo, temporários e recuperação de conclusão
parcial. A admissão e qualificação de falhas ainda estão em desenvolvimento; não
habilitar o runtime antes de verificá-las.

Reprodução com Go compatível com go.mod e dependências autorizadas:

```sh
go test -race ./internal/recoveryreserve ./internal/configpoc -count=1 -timeout=15m
go vet ./internal/recoveryreserve ./internal/configpoc
go build ./...
```

TestReserveCoordinator usa journals/pools temporários reais e motores simulados.
TestReserveArchiveV2 verifica limites, substituições e auditorias ausentes ou de
outro contexto. Encerramentos de processo não comprovam cortes de energia.
Qualificação nativa com espaço finito e motores reais deve ser relatada
separadamente; não há garantia de produção, HA ou resistência a qualquer falha
física.

O harness de volumes copiados aceita `--authorized-debian-v2-reserve-volumes`
com os mesmos sete argumentos de `--authorized-debian-v2-volumes` no
[guia de armazenamento](../storagevol/docs/pt.md). Compile o executável com
`go test -c ./internal/configpoc`. Esse modo explícito prepara os pools dentro
do volume copiado e exige RUN/PASS e `ANDEIVA_NATIVE_R2_CASE_PASS` por caso.
Verifica admissão comum, leitura/repetição e recuperação de capacidade após
esgotar bytes/inodes ou manter aberto um arquivo removido. O filesystem de
128 MiB deve rejeitar Commit Confirmed sem capacidade física para sua conclusão.
Não demonstra conclusão de leases sob esgotamento, reinício completo do
coordenador ou motores reais de tráfego.

