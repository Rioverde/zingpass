// Tiny shared toast helper. Expects an element with id="toast" in the DOM.
(function () {
  const toast = document.getElementById('toast');
  if (!toast) return;

  let timer;

  window.showToast = function (message, type) {
    toast.textContent = message;
    toast.className = 'toast show' + (type ? ' ' + type : '');
    clearTimeout(timer);
    timer = setTimeout(() => toast.classList.remove('show'), 4000);
  };
})();
