// Surface ?verified=1 success after email verification.
(function () {
  const params = new URLSearchParams(window.location.search);
  if (params.get('verified') !== '1') return;

  setTimeout(() => {
    if (typeof showToast === 'function') {
      showToast('Email verified! Please sign in.', 'success');
    }
  }, 0);

  const url = new URL(window.location.href);
  url.searchParams.delete('verified');
  window.history.replaceState({}, '', url);
})();

// Surface OAuth callback failures sent as ?error=...
(function () {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('error');
  if (!code) return;

  const messages = {
    // Legacy aliases (in case anything still emits these).
    oauth_denied: 'GitHub login was cancelled.',
    oauth_invalid_callback: 'Login failed: invalid callback.',
    oauth_state_mismatch: 'Login failed: security check did not match. Please try again.',
    oauth_failed: 'GitHub login failed. Please try again.',

    // Typed application codes from the backend.
    OA0001: 'Your GitHub email is private. Make it public in GitHub settings (Profile → Public email) and try again.',
    OA0002: 'GitHub login was cancelled.',
    OA0003: 'Security check failed — please try again.',
    OA0004: 'Invalid callback from GitHub. Try again.',
    U0001:  'A user with this email already exists.',
    U0003:  'Please verify your email before signing in.',
    U0010:  'This nickname is already taken.',
    A0001:  'This verification link is invalid.',
    A0002:  'This verification link has expired. Request a new one.',
    A0003:  'No verification token provided.',
    A0004:  'This verification link has already been used.',
    S0001:  'Something went wrong on our side. Please try again.',
  };

  // Wait one tick so toast.js has bound window.showToast.
  setTimeout(() => {
    if (typeof showToast === 'function') {
      showToast(messages[code] || 'Login failed', 'error');
    }
  }, 0);

  // Clean the URL so a refresh doesn't re-show the toast.
  const url = new URL(window.location.href);
  url.searchParams.delete('error');
  window.history.replaceState({}, '', url);
})();

const form = document.getElementById('form');
const nickname_input = document.getElementById('nickname-input');
const email_input = document.getElementById('email-input');
const password_input = document.getElementById('password-input');
const repeat_password_input = document.getElementById('repeat-password-input');
const submit_btn = form.querySelector('button[type="submit"]');

const isSignup = nickname_input !== null;

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  const errors = isSignup
    ? getSignupFormErrors(nickname_input.value, email_input.value, password_input.value, repeat_password_input.value)
    : getLoginFormErrors(email_input.value, password_input.value);

  if (errors.length > 0) {
    showToast(errors.join('. '), 'error');
    return;
  }

  submit_btn.disabled = true;

  try {
    const url = isSignup ? '/auth/register' : '/auth/login';
    const payload = isSignup
      ? {
          email: email_input.value.trim(),
          nickname: nickname_input.value.trim(),
          password: password_input.value,
        }
      : {
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
        sessionStorage.setItem('pendingVerifyEmail', email_input.value.trim().toLowerCase());
        showToast('Account created. Check your email…', 'success');
        setTimeout(() => { window.location.href = '/verify'; }, 1200);
      } else {
        if (body.token) sessionStorage.setItem('token', body.token);
        showToast('Logged in. Redirecting…', 'success');
        setTimeout(() => { window.location.href = '/dashboard'; }, 800);
      }
    } else {
      // U0003 = email not verified — send them to the verify page with email prefilled.
      if (body.error && body.error.code === 'U0003') {
        sessionStorage.setItem('pendingVerifyEmail', email_input.value.trim().toLowerCase());
        showToast('Please verify your email first…', 'error');
        setTimeout(() => { window.location.href = '/verify'; }, 1200);
        return;
      }
      showToast((body.error && body.error.message) || 'Request failed', 'error');
    }
  } catch (err) {
    showToast('Network error', 'error');
  } finally {
    submit_btn.disabled = false;
  }
});

function getSignupFormErrors(nickname, email, password, repeatPassword) {
  const errors = [];

  if (!nickname) {
    errors.push('Nickname is required');
    nickname_input.parentElement.classList.add('incorrect');
  } else if (nickname.length < 3) {
    errors.push('Nickname must be at least 3 characters');
    nickname_input.parentElement.classList.add('incorrect');
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

const allInputs = [nickname_input, email_input, password_input, repeat_password_input].filter(Boolean);
allInputs.forEach((input) => {
  input.addEventListener('input', () => {
    if (input.parentElement.classList.contains('incorrect')) {
      input.parentElement.classList.remove('incorrect');
    }
  });
});
