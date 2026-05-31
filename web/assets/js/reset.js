// The reset token comes from the URL query string (set by the email link).
const token = new URLSearchParams(window.location.search).get('token') || '';

if (!token) {
  // No token — there's nothing to do here.
  setTimeout(() => {
    if (typeof showToast === 'function') showToast('Missing or invalid reset link.', 'error');
    setTimeout(() => { window.location.href = '/forgot'; }, 1500);
  }, 0);
}

const form = document.getElementById('reset-form');
const passwordInput = document.getElementById('password-input');
const repeatInput = document.getElementById('repeat-password-input');
const btn = document.getElementById('reset-btn');

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  const password = passwordInput.value;
  const repeat = repeatInput.value;

  if (!password) {
    showToast('Please enter a password', 'error');
    passwordInput.parentElement.classList.add('incorrect');
    return;
  }
  if (password.length < 8) {
    showToast('Password must be at least 8 characters', 'error');
    passwordInput.parentElement.classList.add('incorrect');
    return;
  }
  if (password !== repeat) {
    showToast('Passwords do not match', 'error');
    passwordInput.parentElement.classList.add('incorrect');
    repeatInput.parentElement.classList.add('incorrect');
    return;
  }

  btn.disabled = true;
  try {
    const res = await fetch('/auth/password/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, password }),
    });
    const body = await res.json().catch(() => ({}));

    if (res.ok) {
      showToast('Password updated. You can sign in now.', 'success');
      setTimeout(() => { window.location.href = '/login'; }, 1500);
    } else {
      showToast((body.error && body.error.message) || 'Reset failed', 'error');
    }
  } catch (err) {
    showToast('Network error', 'error');
  } finally {
    btn.disabled = false;
  }
});

[passwordInput, repeatInput].forEach((el) => {
  el.addEventListener('input', () => {
    el.parentElement.classList.remove('incorrect');
  });
});
