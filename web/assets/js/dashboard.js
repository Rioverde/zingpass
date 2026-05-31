// After OAuth callback the backend hands the access token over in a 1-minute,
// non-httpOnly cookie. Lift it into sessionStorage and erase the cookie so it
// is never read or sent again.
(function pickupOAuthAccess() {
  const m = document.cookie.match(/(?:^|;\s*)access_token=([^;]+)/);
  if (!m) return;
  sessionStorage.setItem('token', decodeURIComponent(m[1]));
  document.cookie = 'access_token=; Path=/; Max-Age=-1; SameSite=Lax';
})();

// Guard: no access token → bounce to login.
if (!sessionStorage.getItem('token')) {
  window.location.href = '/login';
}

const logoutBtn = document.getElementById('logoutBtn');

logoutBtn.addEventListener('click', async () => {
  logoutBtn.disabled = true;

  try {
    // Browser will attach refresh cookie automatically.
    // Mobile/JS-only client could also send X-Refresh-Token header.
    await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' });
  } catch (err) {
    // Network failure — keep going; client-side cleanup still matters.
  } finally {
    sessionStorage.removeItem('token');
    showToast('Logged out. Redirecting…', 'success');
    setTimeout(() => { window.location.href = '/login'; }, 600);
  }
});
