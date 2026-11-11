const button = document.querySelector('.mode');
const media = matchMedia('(prefers-color-scheme: dark)');
let choice = null;
try {
  const stored = localStorage.getItem('kf-project-mode');
  if (stored === 'light' || stored === 'dark') choice = stored;
} catch {}
function apply(mode) {
  document.body.dataset.mode = mode;
  document.documentElement.style.colorScheme = mode;
  button.textContent = mode === 'dark' ? 'Dark / Light' : 'Light / Dark';
  button.setAttribute('aria-label', `${button.textContent}: switch to ${mode === 'dark' ? 'light' : 'dark'} mode`);
}
apply(choice ?? (media.matches ? 'dark' : 'light'));
button.addEventListener('click', () => {
  choice = document.body.dataset.mode === 'dark' ? 'light' : 'dark';
  apply(choice);
  try { localStorage.setItem('kf-project-mode', choice); } catch {}
});
media.addEventListener('change', () => {
  if (choice === null) apply(media.matches ? 'dark' : 'light');
});
button.hidden = false;
