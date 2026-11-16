# Lecturas de autoridad activa DHCP

El helper reutiliza el lector de autoridad activa cuando existe la comprobación completa de integridad. Conserva trabajo e identidad seleccionados, reservas físicas, archivo terminal, dependencias y selector final. Arranque, inspección completa, ámbitos fresh/reboot y preflight aislado siguen usando el historial completo. Sin raíz de integridad, el lector continúa siendo completo; no se concede autorización nueva.

Se mantienen las cuatro verificaciones y los plazos originales, sin caché entre solicitudes. Las pruebas cubren ambos lectores, ciclo completo, trabajo/identidad ajenos, reserva sustituida y FinalWork ausente. Reproducción: los mismos comandos de la guía inglesa. Renovación y reinicio real de API requieren calificación Debian separada; los tiempos unitarios no prueban rendimiento del appliance.
