// Prefill email from sessionStorage (set by auth.js after Register or U0003 on Login)
// or ?email=... . The field is locked: this is the address the user signed up with.
(function prefill() {
  const input = document.getElementById('email-input');
  if (!input) return;

  const fromQuery = new URLSearchParams(window.location.search).get('email');
  const fromStorage = sessionStorage.getItem('pendingVerifyEmail');
  const email = fromQuery || fromStorage || '';

  if (!email) {
    // Nothing to verify — bounce back to login so the user can try again.
    window.location.replace('/login');
    return;
  }

  input.value = email;
})();

const form = document.getElementById('resend-form');
const emailInput = document.getElementById('email-input');
const btn = document.getElementById('resend-btn');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = emailInput.value.trim().toLowerCase();
  if (!email) {
    showToast('Please enter your email', 'error');
    return;
  }

  btn.disabled = true;
  try {
    const res = await fetch('/auth/verify/resend', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    if (res.ok) {
      showToast('If the address is registered, a new link has been sent.', 'success');
    } else {
      showToast('Could not send right now. Try again later.', 'error');
    }
  } catch (err) {
    showToast('Network error', 'error');
  } finally {
    btn.disabled = false;
  }
});
