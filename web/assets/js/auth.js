const form = document.getElementById('form');
const firstname_input = document.getElementById('firstname-input');
const email_input = document.getElementById('email-input');
const password_input = document.getElementById('password-input');
const repeat_password_input = document.getElementById('repeat-password-input');
const submit_btn = form.querySelector('button[type="submit"]');

const isSignup = firstname_input !== null;

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  const errors = isSignup
    ? getSignupFormErrors(firstname_input.value, email_input.value, password_input.value, repeat_password_input.value)
    : getLoginFormErrors(email_input.value, password_input.value);

  if (errors.length > 0) {
    showToast(errors.join('. '), 'error');
    return;
  }

  submit_btn.disabled = true;

  try {
    const url = isSignup ? '/auth/register' : '/auth/login';
    const payload = {
      email: email_input.value.trim(),
      password: password_input.value,
    };

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const body = await res.json().catch(() => ({}));

    if (res.ok) {
      if (isSignup) {
        showToast('Account created. Redirecting…', 'success');
        setTimeout(() => { window.location.href = '/login'; }, 1200);
      } else {
        if (body.token) sessionStorage.setItem('token', body.token);
        showToast('Logged in. Redirecting…', 'success');
        setTimeout(() => { window.location.href = '/dashboard'; }, 800);
      }
    } else {
      showToast((body.error && body.error.message) || 'Request failed', 'error');
    }
  } catch (err) {
    showToast('Network error', 'error');
  } finally {
    submit_btn.disabled = false;
  }
});

function getSignupFormErrors(firstname, email, password, repeatPassword) {
  const errors = [];

  if (!firstname) {
    errors.push('Firstname is required');
    firstname_input.parentElement.classList.add('incorrect');
  }
  if (!email) {
    errors.push('Email is required');
    email_input.parentElement.classList.add('incorrect');
  }
  if (!password) {
    errors.push('Password is required');
    password_input.parentElement.classList.add('incorrect');
  } else if (password.length < 8) {
    errors.push('Password must have at least 8 characters');
    password_input.parentElement.classList.add('incorrect');
  }
  if (password !== repeatPassword) {
    errors.push('Password does not match repeated password');
    password_input.parentElement.classList.add('incorrect');
    repeat_password_input.parentElement.classList.add('incorrect');
  }

  return errors;
}

function getLoginFormErrors(email, password) {
  const errors = [];
  if (!email) {
    errors.push('Email is required');
    email_input.parentElement.classList.add('incorrect');
  }
  if (!password) {
    errors.push('Password is required');
    password_input.parentElement.classList.add('incorrect');
  }
  return errors;
}

const allInputs = [firstname_input, email_input, password_input, repeat_password_input].filter(Boolean);
allInputs.forEach((input) => {
  input.addEventListener('input', () => {
    if (input.parentElement.classList.contains('incorrect')) {
      input.parentElement.classList.remove('incorrect');
    }
  });
});
