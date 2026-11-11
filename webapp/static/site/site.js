/* ============================================================================
   Marketing site behaviour: sticky header, mobile menu, scroll reveals,
   copy buttons, docs scroll-spy and small count-up numbers.
   ========================================================================= */

(() => {
  'use strict';

  /* sticky header state */
  const header = document.querySelector('.site-header');
  if (header) {
    const sync = () => header.classList.toggle('is-stuck', window.scrollY > 8);
    sync();
    window.addEventListener('scroll', sync, { passive: true });
  }

  /* mobile navigation */
  const toggle = document.querySelector('.menu-toggle');
  const links = document.querySelector('.nav-links');
  if (toggle && links) {
    toggle.addEventListener('click', () => {
      const open = links.classList.toggle('is-open');
      toggle.setAttribute('aria-expanded', String(open));
    });
    links.addEventListener('click', (event) => {
      if (event.target.closest('a')) {
        links.classList.remove('is-open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && links.classList.contains('is-open')) {
        links.classList.remove('is-open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  /* scroll reveals */
  const reveals = [...document.querySelectorAll('.reveal')];
  if (reveals.length) {
    if ('IntersectionObserver' in window) {
      const observer = new IntersectionObserver((entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      }, { rootMargin: '0px 0px -12% 0px', threshold: 0.12 });
      reveals.forEach((node) => observer.observe(node));
    } else {
      reveals.forEach((node) => node.classList.add('is-visible'));
    }
  }

  /* count-up numbers (skipped when the user prefers reduced motion) */
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const counters = [...document.querySelectorAll('[data-count]')];
  if (counters.length && !reduced && 'IntersectionObserver' in window) {
    const run = (node) => {
      const target = Number(node.dataset.count || 0);
      const started = performance.now();
      const duration = 700;
      const tick = (now) => {
        const progress = Math.min(1, (now - started) / duration);
        node.textContent = String(Math.round(target * (1 - Math.pow(1 - progress, 3))));
        if (progress < 1) requestAnimationFrame(tick);
        else node.textContent = String(target);
      };
      requestAnimationFrame(tick);
    };
    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        run(entry.target);
        observer.unobserve(entry.target);
      }
    }, { threshold: 0.4 });
    counters.forEach((node) => observer.observe(node));
  }

  /* copy buttons on documentation snippets */
  document.querySelectorAll('.prose pre').forEach((pre) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy-btn';
    button.textContent = 'Copy';
    button.dataset.tip = 'Copy snippet';
    button.dataset.tipDesc = 'Copies this command block to the clipboard.';
    button.addEventListener('click', async () => {
      const code = pre.querySelector('code');
      if (!code) return;
      try {
        await navigator.clipboard.writeText(code.textContent.trim());
        button.textContent = 'Copied';
        setTimeout(() => { button.textContent = 'Copy'; }, 1600);
      } catch {
        button.textContent = 'Blocked';
        setTimeout(() => { button.textContent = 'Copy'; }, 1600);
      }
    });
    pre.append(button);
  });

  /* docs scroll-spy */
  const sideLinks = [...document.querySelectorAll('.docs-link[href^="#"]')];
  if (sideLinks.length && 'IntersectionObserver' in window) {
    const map = new Map();
    sideLinks.forEach((link) => {
      const section = document.getElementById(link.getAttribute('href').slice(1));
      if (section) map.set(section, link);
    });
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        sideLinks.forEach((link) => link.classList.remove('is-active'));
        const link = map.get(entry.target);
        if (link) link.classList.add('is-active');
      });
    }, { rootMargin: '-20% 0px -65% 0px' });
    map.forEach((_, section) => observer.observe(section));
  }

  /* footer year */
  document.querySelectorAll('[data-year]').forEach((node) => {
    node.textContent = String(new Date().getFullYear());
  });
})();
