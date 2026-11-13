# Ciclo de vida da administração

O target exige o gestor de namespaces e o helper, mas apenas solicita o socket HTTPS e a API através de Wants. Parar ou falhar a API/socket preserva as regras aplicadas, o gestor de namespaces e o prazo independente do helper. A paragem explícita do target e falhas do helper/namespaces mantêm o encerramento coordenado. Os limites de reinício da API continuam; a administração pode ficar degradada sem eliminar o plano de dados.

Validação: `bash packaging/preview/tests/api-lifetime-unit-graph.sh`. Verifica dependências, não tráfego ou falhas reais do systemd; exigem testes isolados no Debian.
