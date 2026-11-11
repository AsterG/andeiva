import type { Locale } from '../messages.js';

const en = {
  move: 'Move window', center: 'Center window', close: 'Close editor',
  moveHint: 'Drag the title bar, or activate Move window and use arrow keys. Shift moves one pixel; Home centers. Enter keeps the position; Escape cancels the move.',
  moving: 'Moving window', placed: 'Window position kept', cancelled: 'Window move cancelled',
};
export type FloatingWindowMessages = typeof en;
export const floatingWindowMessages: Record<Locale, FloatingWindowMessages> = {
  en,
  es: {
    move: 'Mover ventana', center: 'Centrar ventana', close: 'Cerrar editor',
    moveHint: 'Arrastre la cabecera o active Mover ventana y use las flechas. Mayús mueve un píxel; Inicio centra. Intro conserva la posición; Escape cancela el movimiento.',
    moving: 'Moviendo ventana', placed: 'Posición de ventana conservada', cancelled: 'Movimiento de ventana cancelado',
  },
  pt: {
    move: 'Mover janela', center: 'Centralizar janela', close: 'Fechar editor',
    moveHint: 'Arraste o cabeçalho ou ative Mover janela e use as setas. Shift move um pixel; Home centraliza. Enter mantém a posição; Escape cancela o movimento.',
    moving: 'Movendo janela', placed: 'Posição da janela mantida', cancelled: 'Movimento da janela cancelado',
  },
};
