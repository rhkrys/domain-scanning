// Accordion: collapsible rows and boxes, collapsed by default.
//
// Markup (see accordion.css for the two looks, "rows" and "boxes"):
//   <div data-accordion="rows">
//     <div class="acc-item">
//       <h3 class="acc-heading">
//         <button class="acc-trigger" type="button" aria-expanded="false" aria-controls="x">
//           Question <span class="acc-chevron" aria-hidden="true"></span>
//         </button>
//       </h3>
//       <div class="acc-panel" id="x" role="region" hidden>Answer</div>
//     </div>
//   </div>
//
// Keyboard: Enter or Space toggles (native button), Up and Down move between
// rows, Home and End jump to the first and last. A link to a row's id opens it.
(function () {
  'use strict';

  function setOpen(trigger, open) {
    var panel = document.getElementById(trigger.getAttribute('aria-controls'));
    trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (panel) panel.hidden = !open;
    var item = trigger.closest('.acc-item');
    if (item) item.classList.toggle('is-open', open);
  }

  function init(root) {
    var triggers = Array.prototype.slice.call(root.querySelectorAll('.acc-trigger'));
    triggers.forEach(function (t, i) {
      setOpen(t, t.getAttribute('aria-expanded') === 'true');
      t.addEventListener('click', function () {
        setOpen(t, t.getAttribute('aria-expanded') !== 'true');
      });
      t.addEventListener('keydown', function (e) {
        var next = null;
        if (e.key === 'ArrowDown') next = triggers[i + 1] || triggers[0];
        else if (e.key === 'ArrowUp') next = triggers[i - 1] || triggers[triggers.length - 1];
        else if (e.key === 'Home') next = triggers[0];
        else if (e.key === 'End') next = triggers[triggers.length - 1];
        if (next) {
          e.preventDefault();
          next.focus();
        }
      });
    });
  }

  function openFromHash() {
    var id = window.location.hash.slice(1);
    if (!id) return;
    var target = document.getElementById(id);
    var item = target && target.closest('.acc-item');
    var trigger = item && item.querySelector('.acc-trigger');
    if (trigger) setOpen(trigger, true);
  }

  function start() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-accordion]'), init);
    openFromHash();
    window.addEventListener('hashchange', openFromHash);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
