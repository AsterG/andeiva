# Leituras de autoridade ativa DHCP

O helper reutiliza o leitor de autoridade ativa quando existe a verificação completa de integridade. Mantém trabalho e identidade selecionados, reservas físicas, arquivo terminal, dependências e seletor final. Inicialização, inspeção completa, escopos fresh/reboot e preflight isolado continuam usando o histórico completo. Sem raiz de integridade, o leitor permanece completo; nenhuma nova autorização é concedida.

As quatro verificações e os prazos originais permanecem, sem cache entre solicitações. Os testes cobrem ambos os leitores, ciclo completo, trabalho/identidade alheios, reserva substituída e FinalWork ausente. Reprodução: os mesmos comandos do guia inglês. Renovação e reinício real da API exigem qualificação Debian separada; tempos unitários não comprovam desempenho do appliance.
