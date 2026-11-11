export type WindowPosition = { left: number; top: number };
export type WindowViewport = WindowPosition & { width: number; height: number };

export function placeFloatingWindow(position: WindowPosition | null, size: { width: number; height: number }, viewport: WindowViewport, inset: number): WindowPosition {
  const minLeft = viewport.left + inset;
  const minTop = viewport.top + inset;
  const maxLeft = Math.max(minLeft, viewport.left + viewport.width - size.width - inset);
  const maxTop = Math.max(minTop, viewport.top + viewport.height - size.height - inset);
  return {
    left: Math.max(minLeft, Math.min(position?.left ?? viewport.left + (viewport.width - size.width) / 2, maxLeft)),
    top: Math.max(minTop, Math.min(position?.top ?? viewport.top + (viewport.height - size.height) / 2, maxTop)),
  };
}
