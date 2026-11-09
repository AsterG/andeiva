// Apply the explicit browser preference before styles or application content paint.
(() => {
  let theme = 'light';
  try {
    if (localStorage.getItem('andeiva.preview.theme') === 'dark') theme = 'dark';
  } catch {
    // Storage restrictions must not prevent the default theme from loading.
  }
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
})();
