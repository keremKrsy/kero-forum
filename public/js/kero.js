(function () {
  'use strict';

  const userMenu = document.getElementById('userMenu');
  if (userMenu) {
    const trigger = userMenu.querySelector('.user-menu-trigger');
    trigger?.addEventListener('click', (e) => {
      e.stopPropagation();
      const open = userMenu.classList.toggle('open');
      trigger.setAttribute('aria-expanded', open);
    });
    document.addEventListener('click', () => {
      userMenu.classList.remove('open');
      trigger?.setAttribute('aria-expanded', 'false');
    });
  }

  const mobileToggle = document.getElementById('mobileToggle');
  const mainNav = document.getElementById('mainNav');
  mobileToggle?.addEventListener('click', () => {
    mainNav?.classList.toggle('open');
    mobileToggle.classList.toggle('active');
  });

  document.querySelectorAll('.color-picker .color-option input').forEach((input) => {
    input.addEventListener('change', () => {
      document.querySelectorAll('.color-option').forEach((o) => o.classList.remove('selected'));
      input.closest('.color-option')?.classList.add('selected');
    });
  });

  document.querySelectorAll('.toast-msg').forEach((el) => {
    setTimeout(() => el.classList.add('fade-out'), 4000);
  });
})();
