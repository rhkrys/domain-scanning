// Pop-ups: a button with data-popup="id" opens <dialog id="id"> as a modal.
// Escape, the close button, or a click on the backdrop closes it, and focus
// goes back to the button that opened it.
(function () {
  'use strict';

  function wire(button) {
    var dialog = document.getElementById(button.getAttribute('data-popup'));
    if (!dialog || typeof dialog.showModal !== 'function') return;
    button.setAttribute('aria-haspopup', 'dialog');
    button.addEventListener('click', function () {
      dialog.showModal();
      var first = dialog.querySelector('.popup-close');
      if (first) first.focus();
    });
    dialog.addEventListener('close', function () {
      button.focus();
    });
  }

  function wireDialog(dialog) {
    Array.prototype.forEach.call(dialog.querySelectorAll('.popup-close'), function (btn) {
      btn.addEventListener('click', function () {
        dialog.close();
      });
    });
    // A click on the backdrop lands on the dialog element itself, not its content.
    dialog.addEventListener('click', function (e) {
      if (e.target === dialog) dialog.close();
    });
  }

  function start() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-popup]'), wire);
    Array.prototype.forEach.call(document.querySelectorAll('dialog.popup'), wireDialog);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
