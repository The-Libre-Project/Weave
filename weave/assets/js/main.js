// LibreWin OS Website

// ── Theme toggle ──────────────────────────────────────────────
(function () {
  const html = document.documentElement;
  const btn = document.getElementById('theme-toggle');

  // Detect OS preference
  function osPrefersDark() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  // Get effective visual theme ('dark' | 'light')
  function effectiveTheme(stored) {
    if (stored === 'dark') return 'dark';
    if (stored === 'light') return 'light';
    return osPrefersDark() ? 'dark' : 'light'; // auto
  }

  function updateButton(stored) {
    const visual = effectiveTheme(stored);
    // Icon: sun in dark mode (click → light), moon in light mode (click → dark)
    btn.querySelector('.theme-icon').textContent = visual === 'dark' ? '☀' : '☾';
    btn.querySelector('.theme-label').textContent = visual === 'dark' ? 'Switch to Light mode' : 'Switch to Dark mode';
  }

  function applyTheme(stored) {
    html.setAttribute('data-theme', stored || 'auto');
    updateButton(stored);
  }

  // Toggle: auto → opposite of OS; forced → back to auto
  function toggle() {
    const current = localStorage.getItem('theme'); // null / 'light' / 'dark'
    if (!current || current === 'auto') {
      // Switch to forced opposite of OS
      const forced = osPrefersDark() ? 'light' : 'dark';
      localStorage.setItem('theme', forced);
      applyTheme(forced);
    } else {
      // Return to auto
      localStorage.removeItem('theme');
      applyTheme(null);
    }
  }

  btn.addEventListener('click', toggle);

  // Init
  const saved = localStorage.getItem('theme');
  applyTheme(saved);

  // Update if OS theme changes while page is open
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    const current = localStorage.getItem('theme');
    if (!current || current === 'auto') updateButton(null);
  });
})();

// ── Active nav link on scroll ─────────────────────────────────
(function () {
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav-links a[href^="#"]');

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          navLinks.forEach((link) => {
            link.classList.toggle(
              'active',
              link.getAttribute('href') === '#' + entry.target.id
            );
          });
        }
      });
    },
    { rootMargin: '-40% 0px -55% 0px' }
  );

  sections.forEach((s) => observer.observe(s));
})();
