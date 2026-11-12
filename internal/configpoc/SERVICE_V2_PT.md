# Adaptador autenticado de configuração v2

ServiceV2 reutiliza coordenador e catálogo; somente abre armazenamento preparado.
Não migra, ativa runtime ou anuncia capacidades. SubjectID e CredentialRevision
são mirrors opcionais inseparáveis da conta, sujeitos ao registro canônico. Sem
ambos, autenticação v1 permanece disponível, mas não autoriza v2. A identidade
não deriva de nome, credencial, UID ou requisição.

O binding opaco exige sessão real do Manager fixado. Cada operação verifica
logout, prazos, inatividade, papel e mirrors antes do lock de armazenamento;
registro e ação usam o mesmo lock. Auth e armazenamento não mantêm locks
sobrepostos. Logout posterior à autenticação não cancela trabalho já admitido.
Viewer somente lê estado/projeção; catálogo e mutações exigem admin. Respostas
não incluem revisão de credencial, token ou internals do binding.

[Comandos e limites](SERVICE_V2.md). Testes unitários/race, revogação concorrente,
propriedade alheia, reabertura e transações com motores simulados passaram,
incluindo execução Debian sem privilégios. Não ativa serviços do appliance ou
regras reais. Transporte Web/CLI/API, TLS/CSRF, cutover, capacidade física e proof
mapper de serviços locais continuam pendentes. Nenhum histórico protegido é
excluído; não há afirmação de quota física.
