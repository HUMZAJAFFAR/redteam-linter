/* ============================================================================
   Cursor-following tooltip.

   Usage:  <button data-tip="Run scan" data-tip-desc="Checks the target against
                  every active sink rule.">…</button>

   Behaviour
   ---------
   * appears after a short delay next to the cursor (never on touch/coarse
     pointers, where it would stick);
   * follows the pointer with requestAnimationFrame and is clamped to the
     viewport, so it never leaves the screen;
   * for keyboard users it is anchored under the focused element instead;
   * hides on pointerout, blur, Escape, scroll and click.
   ========================================================================= */

(() => {
  'use strict';

  const SHOW_DELAY = 120;
  const OFFSET_X = 16;
  const OFFSET_Y = 18;
  const EDGE = 12;

  const supportsHover = () =>
    window.matchMedia('(hover: hover) and (pointer: fine)').matches;

  let node = null;
  let labelEl = null;
  let descEl = null;
  let active = null;
  let mode = 'pointer';
  let visible = false;
  let timer = 0;
  let frame = 0;
  const pointer = { x: 0, y: 0 };

  function build() {
    if (node) return;
    node = document.createElement('div');
    node.id = 'rt-tooltip';
    node.className = 'rt-tooltip';
    node.setAttribute('role', 'tooltip');
    node.setAttribute('aria-hidden', 'true');
    labelEl = document.createElement('span');
    labelEl.className = 'rt-tooltip-label';
    descEl = document.createElement('span');
    descEl.className = 'rt-tooltip-desc';
    node.append(labelEl, descEl);
    document.body.append(node);
  }

  function place() {
    if (!node || !visible) return;
    const box = node.getBoundingClientRect();
    const width = box.width;
    const height = box.height;
    let x;
    let y;

    if (mode === 'focus' && active) {
      const anchor = active.getBoundingClientRect();
      x = anchor.left + anchor.width / 2 - width / 2;
      y = anchor.bottom + 8;
      if (y + height > window.innerHeight - EDGE) y = anchor.top - height - 8;
    } else {
      x = pointer.x + OFFSET_X;
      y = pointer.y + OFFSET_Y;
      if (x + width > window.innerWidth - EDGE) x = pointer.x - width - OFFSET_X;
      if (y + height > window.innerHeight - EDGE) y = pointer.y - height - OFFSET_Y;
    }

    x = Math.max(EDGE, Math.min(x, window.innerWidth - width - EDGE));
    y = Math.max(EDGE, Math.min(y, window.innerHeight - height - EDGE));

    node.style.left = Math.round(x) + 'px';
    node.style.top = Math.round(y) + 'px';
  }

  function show(element, nextMode) {
    if (!element || !element.dataset.tip) return;
    build();
    active = element;
    mode = nextMode;
    labelEl.textContent = element.dataset.tip;
    descEl.textContent = element.dataset.tipDesc || '';
    node.classList.add('is-visible');
    node.setAttribute('aria-hidden', 'false');
    element.setAttribute('aria-describedby', 'rt-tooltip');
    visible = true;
    place();
  }

  function hide() {
    window.clearTimeout(timer);
    if (!visible) {
      active = null;
      return;
    }
    visible = false;
    node.classList.remove('is-visible');
    node.setAttribute('aria-hidden', 'true');
    if (active) active.removeAttribute('aria-describedby');
    active = null;
  }

  function requestShow(element, nextMode) {
    if (!element || !element.dataset.tip) return;
    if (element === active && visible) return;
    if (element !== active) hide();
    if (nextMode === 'focus') {
      show(element, 'focus');
      return;
    }
    window.clearTimeout(timer);
    timer = window.setTimeout(() => show(element, 'pointer'), SHOW_DELAY);
  }

  document.addEventListener('pointerover', (event) => {
    if (!supportsHover()) return;
    const element = event.target.closest('[data-tip]');
    if (!element) return;
    pointer.x = event.clientX;
    pointer.y = event.clientY;
    requestShow(element, 'pointer');
  });

  document.addEventListener('pointermove', (event) => {
    if (!supportsHover() || !visible || mode !== 'pointer') return;
    pointer.x = event.clientX;
    pointer.y = event.clientY;
    if (frame) return;
    frame = window.requestAnimationFrame(() => {
      frame = 0;
      place();
    });
  });

  document.addEventListener('pointerout', (event) => {
    const element = event.target.closest('[data-tip]');
    if (!element) return;
    const next = event.relatedTarget;
    if (next && element.contains(next)) return;
    hide();
  });

  document.addEventListener('focusin', (event) => {
    const element = event.target.closest('[data-tip]');
    if (!element) return;
    requestShow(element, 'focus');
  });

  document.addEventListener('focusout', hide);
  document.addEventListener('pointerdown', hide, true);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') hide();
  }, true);
  window.addEventListener('scroll', hide, { passive: true, capture: true });

  window.RTTooltip = { hide };
})();
