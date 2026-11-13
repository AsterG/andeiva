# Fixture de integração IPC routed v3 — RED

`TestRoutedIPCV3SharedStoreLifecycle` usa store compartilhado, reservas R2, G1,
leitor selecionado, RoutedStoreSourceV3, wrapper Unix com credenciais reais,
RoutedSessionV3, RoutedRemoteAuthority e Group. Somente I/O kernel/rede usa
fixtures tipadas. Executa em Linux sem root. UID2000 do helper é scope lógico
diferente do dono real do store; não prova três UIDs isolados nem tráfego nativo.

O freeze permanece RED: Boot4 preserva as duas regras importadas sem L3;
Stage4/Validate4/Commit4/Confirm4/Save4 passam. Após Stage6, Validate6 retorna
ANDEIVA_ADMIN_HELPER_UNAVAILABLE. Sem race, WSL/Go1.27.4: PrepareView43/581/920 ms
e depois3.000320499 s com erro na leitura selecionada; Resolve arm/apply/confirm
1.027/1.167/1.494 s. A sessão termina ANDEIVA_PREVIEW_UNAVAILABLE. Total10.447 s.
Timeouts, validadores e protocolo permanecem intactos. Restart confirmado e inversa
estão escritos, mas não alcançados; expiração e aceitação completa aguardam o fix
do leitor. Não é qualificação nativa de Boot4.

Reproduzir com Go1.27.4, cache offline e usuário Linux não root (root ignora este perfil):

```sh
GOPROXY=off GOSUMDB=off go test ./internal/previewruntime -run '^TestRoutedIPCV3SharedStoreLifecycle$' -count=1 -timeout=10m -v
```

Apenas a fixture converte diretórios temporários para02750 e arquivos para0640
após fechar writers privados; checkpoint.lock permanece0600. Não altera permissões
de produção. Handshake Unix precede cada abertura do writer compartilhado.
Nenhum caminho/hash de fixture concede autoridade.
