# Firewall Alpha Preview — Português

Instalação experimental Debian 13 AMD64 no VMware. As regras são aplicadas em
namespaces isolados; não protegem o host nem encaminham tráfego de produção.
Mantenha um snapshot recuperável e leia os [limites do runtime](../README.md).

## Instalação

A URL raiz de administração abre a console autenticada. Regras, Dashboard,
Auditoria, Configuração e Registros de tráfego compartilham a sessão e os
contratos transacionais existentes. Consulte o [guia da console](../../../frontend/docs/console-pt.md)
para alterações pendentes, confirmação, persistência em Startup e teclado.
Largura de banda por interface, atribuição por país e seleção de objetos
persistentes permanecem indisponíveis até implementar essas capacidades.


Baixe `firewall-alpha-preview-debian13-amd64` de uma execução Quality aprovada no
repositório privado. A retenção é de três dias. Verifique o commit revisado e
`SHA256SUMS`; checksum não é assinatura do fornecedor. Transfira por um meio
autorizado. As dependências Debian devem existir; não são baixadas automaticamente.

```bash
sha256sum -c SHA256SUMS
sudo dpkg -i ./andeiva-firewall-preview_0.1.0~alpha<BUILD>_amd64.deb
sudo install -o root -g root -m 0644 \
  /etc/andeiva-preview/config.json.example /etc/andeiva-preview/config.json
sudoedit /etc/andeiva-preview/config.json
```

Substitua `<BUILD>` pela versão baixada. Configure IP/porta LAN, interface LAN e
prefixo explícito do cliente autorizado. `192.0.2.1` e `CHANGE_ME` são exemplos.
O prefixo de origem é independente do endereço do servidor; use `/32` se apenas
uma estação precisar de acesso. Não selecione WAN na instalação inicial.
Mantenha os nomes das contas de serviço fornecidos.

```bash
sudo /usr/lib/andeiva-preview/andeiva-preview provision
sudo systemctl daemon-reload
sudo systemctl enable --now andeiva-preview.target
sudo /usr/lib/andeiva-preview/andeiva-preview health
sudo systemctl status andeiva-preview.target \
  andeiva-preview-api.service andeiva-preview-helper.service \
  andeiva-preview-namespaces.service --no-pager
```

Provision não substitui silenciosamente uma instalação existente. Estado parcial
ou inválido bloqueia a inicialização e deve ser preservado para diagnóstico.
Identidades, credenciais, certificados e estado persistem durante atualizações.

## Acesso e uso

No cliente LAN autorizado, confie explicitamente na CA de
`/var/lib/andeiva-preview/ca.crt` após verificar sua procedência. A confiança do
Windows e suas rotas não são alteradas automaticamente. Abra o endereço HTTPS
configurado e `/firewall`; não desative a verificação do certificado.

As credenciais iniciais `admin-a`, `admin-b` e `viewer` ficam em arquivos JSON
root-only em `/var/lib/andeiva-preview/operator/`. Obtenha a credencial escolhida
privadamente pelo console da VM; nunca a copie para logs, issues ou pacotes de
suporte. Viewer não altera regras nem lê histórico protegido. MFA de produção
não está implementado.

A CLI instalada é `andeiva`. Um cliente Linux da LAN utiliza a mesma versão,
CA explícita e arquivo de credencial do próprio usuário com modo 0600:

```bash
andeiva firewall status --url https://<LAN-IP>:9443 \
  --ca-file ./ca.crt --credentials-file ./admin-a.json
sudo /usr/lib/andeiva-preview/andeiva-preview probe --protocol tcp --port 18080
sudo /usr/lib/andeiva-preview/andeiva-preview probe --protocol udp --port 18080
```

Execute os comandos `probe` na VM. Siga o [guia administrativo](../../../internal/firewalladmin/docs/pt.md)
para o esquema comum, Stage, Validate, Commit, Confirm, Save e Rollback,
substituindo URL/caminhos temporários pelos do preview. As observações por regra
são amostras limitadas, não conexões individuais. Reiniciar a API invalida sessões
e cria um novo stream de tráfego.

## Recuperação, atualização e remoção

Antes de criar os namespaces isolados, a inicialização exige dez segundos contínuos
sem alterações nas observações de rede do host, com limite de trinta segundos.
Isso não garante que o DHCP terminou. Uma alteração posterior continua interrompendo
o preview; ele não modifica rotas para restaurar o estado inicial. Se a limpeza
encontrar um pin ocupado, preserve-o e siga o procedimento de reinicialização
autorizada abaixo. Não force a desmontagem nem apague metadados para iniciar.

O teste nativo opcional requer Bash e `jq` previamente instalados a partir de
pacotes Debian offline verificados. Revise o script e o snapshot primeiro:

```bash
sudo bash /usr/share/doc/andeiva-firewall-preview/tests/native.sh --ack-isolated-debian13-vm
```

Sem opções adicionais, observa saúde, sondas, recursos e invariância do host.
`--api-failure` interrompe apenas a API; `--lifecycle` para e inicia a preview.
Ambas interrompem a administração. Relatórios privados de root ficam em
`/var/tmp`; não comprovam paridade transacional nem deduzem a política esperada
de uma sonda bem-sucedida. Verifique separadamente contra a revisão pretendida.

A recuperação automática da API preserva o prazo do helper. Parar API/socket
preserva target, helper e namespaces. A falha do helper encerra todo o
preview. Pare o target, espere API, socket, helper e namespaces ficarem inativos
e depois inicie; não presuma que `restart target` seja atômico. Reinício de serviço
no mesmo boot restaura Running; reiniciar a VM seleciona Startup salvo. Journal
incerto bloqueia a publicação de revisões.

Ao esgotar o limite de reinicializações da API, API/socket podem ficar em falha
enquanto target, helper e namespaces mantêm a última política verificada.
Administração e observações de tráfego da API ficam indisponíveis; `target active`
não significa prontidão. Pare o target e verifique a limpeza dos recursos próprios.
Se API/socket continuarem em falha, execute
`systemctl reset-failed andeiva-preview-api.service andeiva-preview-api.socket`
antes de iniciar explicitamente o target. Não apague nem redefina marcadores de
recuperação dos namespaces para contornar outra falha de limpeza.

Uma falha abrupta do daemon de namespaces pode deixar metadata ou um pin.
Preserve as evidências: a recuperação automática é bloqueada. Uma reinicialização
autorizada da VM remove recursos voláteis. Não apague journal, marcadores ou pins
para contornar a verificação.

Antes de atualizar, pare o target e faça backup protegido de `/etc/andeiva-preview`
e `/var/lib/andeiva-preview`. Verifique o novo artifact e instale com `dpkg -i`.
O target fica parado para revisão; inicie explicitamente após verificar
compatibilidade. Identidades e estado são preservados. Não há downgrade
automático nem atualizador de appliance assinado.

```bash
sudo systemctl disable --now andeiva-preview.target
sudo dpkg --remove andeiva-firewall-preview
```

Configuração, credenciais, journal e auditoria são preservados. Desativação
definitiva e destruição segura exigem ação explícita. Não publique esses arquivos.
Diagnóstico local: `journalctl -u andeiva-preview-api.service`; disponibilidade: health.

Auditoria e journal têm limites finitos e falham de forma fechada ao esgotá-los.
Nunca trunque registros protegidos para recuperar acesso. TLS expira ao terminar
sua validade. Renovação automática, arquivamento, alterações em múltiplas
interfaces e Local Service Policy Manager têm gates separados. Contratos não
comprovam integrações. Registre a execução nativa antes de validar o preview.

## Versão instalada do produto

Após entrar, abra Sistema para consultar a versão ANDEIVA informada pela API em
execução. Uma compilação sem identidade de pacote aparece como desenvolvimento;
a versão não é inferida dos arquivos do navegador. Este runtime não possui
catálogo verificado de atualizações e informa disponibilidade indisponível.

A consulta autenticada pela CLI usa o mesmo endpoint e permissões:

```sh
andeiva system info --url https://ENDERECO_LAN:9443 --ca-file /trusted/ca.crt --credentials-file /private/operator.json
```

`andeiva --version` informa a compilação local da CLI, que pode diferir do
appliance conectado. A validação do pacote verifica se essa identidade coincide
com sua versão Debian. Apenas a identidade do produto ANDEIVA é retornada, sem
versões do sistema operacional, kernel ou motores.

### Política preservada ao parar a administração

No Debian de laboratório recuperável, execute o teste nativo do pacote com
`--ack-isolated-debian13-vm --api-stop`. Para API e socket, verifica processos,
metadados e política efetiva do kernel, compara seis testes reais TCP/UDP e
reinicia a administração. Uma falha tenta restaurar a administração. Não valida
a intenção da política, migração, reinicialização ou routing.