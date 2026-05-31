const form = document.getElementById('forgot-form');
const emailInput = document.getElementById('email-input');
const btn = document.getElementById('forgot-btn');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = emailInput.value.trim().toLowerCase();
  if (!email) {
    showToast('Please enter your email', 'error');
    return;
  }

  btn.disabled = true;
  try {
    const res = await fetch('/auth/password/forgot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    if (res.ok) {
      showToast('If the address is registered, a reset link is on its way.', 'success');
      setTimeout(() => { window.location.href = '/login'; }, 1500);
    } else {
      showToast('Could not send right now. Try again later.', 'error');
    }
  } catch (err) {
    showToast('Network error', 'error');
  } finally {
    btn.disabled = false;
  }
});
