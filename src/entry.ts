if (document.documentElement.classList.contains('device-handoff')) {
  const button = document.querySelector<HTMLButtonElement>('#handoff-copy');
  button?.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(location.href);
      button.textContent = 'Link copied';
    } catch {
      button.textContent = 'Copy the address bar link';
    }
  });
} else {
  void import('./main');
}
