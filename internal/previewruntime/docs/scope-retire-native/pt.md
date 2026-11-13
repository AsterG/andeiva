# Qualificação do core de retirada de scope

Estado: fixture implementada; execução nativa e medições pendentes. Um skip sem
privilégios não comprova qualificação nativa.

Somente Root, em laboratório Debian 13 autorizado sem
`andeiva-preview-grouped.service` nem seu socket. Não executar em CI, WSL
privilegiado ou appliance instalado. Duas invocações reais: a primeira persiste
sete anchors antes de L2/Boot, inicia API sem capacidades/helper com NET_ADMIN,
verifica Boot/readback, espera os filhos e encerra a si mesma com SIGKILL.
A segunda recebe sete FD, testa recusa com lock ocupado e executa o core real
com leitor capless, G1/R2, drain, desmontagem, Drop e recibo. ENODEV preserva
evidências e falha; não significa retirada concluída.

RootDirectory e passwd/group privados; pais veth e MACVLAN somente em namespaces
isolados, sem endereços, rotas ou regras do host. Os pais modelam links externos
e não fazem parte do recibo do gateway. Seus pins ficam no MNT privado antigo.
A projeção operacional schema2 preserva exatamente Boot/Run/Host/GW do bootstrap
schema1; não altera a identidade selecionada.

Escopo: core com raízes reais fornecidas diretamente. Não qualifica loader,
procedência de migração, restart managed, reboot ou handoff management de oito
FD. A árvore de integração precisa do dispatch TestMain do preflight e consultas
fixas systemctl com `SYSTEMD_OFFLINE=0` dentro de RootDirectory; LocalOrigin não
é enfraquecido.
RootDirectory, PrivateMounts, MainPID e InvocationID são consultados no manager
real; sem leitura de symlinks do PID1 ou SYS_PTRACE adicional. O driver rejeita
aliases de caminho por comparação canônica e exige PASS/exit da invocação atual.

```sh
go test -race ./internal/previewruntime -run '^TestRoutedScopeRetireV3Native' -count=1 -v
go vet ./internal/previewruntime
go test -c ./internal/previewruntime -o /absolute/output/scope-retire.test
bash -n packaging/preview/tests/scope-retire-native.sh
# Somente Root, após revisão do artefato e invariantes:
bash packaging/preview/tests/scope-retire-native.sh --isolated-lab /root-owned-0755-directory/scope-retire.test
```

Limites: duas invocações, timeout de teste 90 segundos, 256 FD, 128 tarefas,
384 MiB. SYS_ADMIN pertence à fixture, não ao helper. Falhas preservam unidade,
FDstore, manifest, slot e arquivos; sem stop automático ou remoção recursiva.
Sucesso exige segunda InvocationID correlacionada, FDstore vazio e MainPID zero
antes de parar essa unidade. Preservar journal, propriedades, hashes e recibo.
Root deve comparar endereços/rotas/rules IPv4/IPv6, nftables, forwarding,
namespaces e mountinfo do PID1, registrando CPU/RAM reais.

[English](en.md) · [Español](es.md)
