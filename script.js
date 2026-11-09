/* =========================================================
   HabalGo – script.js (login only: email + password)
   Sections: Data · Storage · AuthService · Validation · UI · Router
   ========================================================= */

/* ---------- Data: pre-approved riders ----------
   A real backend / database would replace this list.
   Hash = SHA-256 of "email:password". */
const RIDERS = [
  { email: 'juan@habalgo.com',  hash: '6ef3248a42414de78b461bee0fac6056c4f9e674e241c831b4dabb5e32762f56', name: 'Juan Dela Cruz', riderId: 'HG-100001', status: 'verified' },
  { email: 'maria@habalgo.com', hash: '66ffd8e8f6b6dddea3ef8b0ac8d4409abfba8ce8906a596e47d35ff3921a9de6', name: 'Maria Santos',   riderId: 'HG-100002', status: 'verified' },
  { email: 'pedro@habalgo.com', hash: 'b782399d6c76fadae022236b7df6d57c50ccc8e20424eb5f99d24248d933af6d', name: 'Pedro Reyes',    riderId: 'HG-100003', status: 'pending'  }
];

const MAX_TRIES = 5, LOCK_SECONDS = 30, IDLE_MS = 15 * 60 * 1000;

/* ---------- Storage helpers (safe if storage is blocked) ---------- */
const Store = {
  get(k, fb, area = localStorage) { try { const v = area.getItem(k); return v ? JSON.parse(v) : fb; } catch { return fb; } },
  set(k, v, area = localStorage) { try { area.setItem(k, JSON.stringify(v)); return true; } catch { return false; } },
  del(k, area = localStorage) { try { area.removeItem(k); } catch {} }
};

/* ---------- Auth service ---------- */
const AuthService = (() => {
  const SESSION = 'habalgo:session', LOCK = 'habalgo:lock';
  const mem = { session: null };
  const norm = e => e.trim().toLowerCase();
  const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');

  // NOTE: client-side check is for the prototype only. Production needs server-side authentication.
  async function sha256(text) {
    if (!(window.crypto && crypto.subtle)) throw new Error('SECURE_CONTEXT');
    return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  }
  const publicRider = r => r ? { email: r.email, name: r.name, riderId: r.riderId, status: r.status } : null;

  return {
    lockLeft() {
      const until = Store.get(LOCK, { until: 0 }).until;
      return Math.max(0, Math.ceil((until - Date.now()) / 1000));
    },
    async login(email, password, remember) {
      if (this.lockLeft() > 0) return { ok: false, locked: true };
      email = norm(email);
      let digest;
      try { digest = await sha256(email + ':' + password); }
      catch { return { ok: false, error: 'Secure connection (HTTPS) is required to log in.' }; }

      const rider = RIDERS.find(r => r.email === email && r.hash === digest);
      const lock = Store.get(LOCK, { n: 0, until: 0 });
      if (!rider) {
        lock.n += 1;
        if (lock.n >= MAX_TRIES) { lock.until = Date.now() + LOCK_SECONDS * 1000; lock.n = 0; Store.set(LOCK, lock); return { ok: false, locked: true }; }
        Store.set(LOCK, lock);
        return { ok: false, error: 'Incorrect email or password.' };
      }
      Store.del(LOCK);
      this.logout(true);
      const area = remember ? localStorage : sessionStorage;
      if (!Store.set(SESSION, { email: rider.email }, area)) mem.session = { email: rider.email };
      return { ok: true };
    },
    current() {
      const s = Store.get(SESSION, null, localStorage) ?? Store.get(SESSION, null, sessionStorage) ?? mem.session;
      return s ? publicRider(RIDERS.find(r => r.email === s.email)) : null;
    },
    logout() { Store.del(SESSION, localStorage); Store.del(SESSION, sessionStorage); mem.session = null; }
  };
})();

/* ---------- Validation ---------- */
const Validate = {
  email: v => !v.trim() ? 'Email is required.' : /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.trim()) ? '' : 'Enter a valid email address.',
  password: v => !v ? 'Password is required.' : v.length < 8 ? 'Password must be at least 8 characters.' : ''
};

/* ---------- UI helpers ---------- */
const $ = id => document.getElementById(id);
const flash = (type, text) => { const m = $('msg'); m.className = 'msg show ' + type; m.textContent = text; };
const clearFlash = () => { $('msg').className = 'msg'; };

function setErr(id, text) {
  document.querySelector(`[data-for="${id}"]`).textContent = text;
  $(id).classList.toggle('bad', !!text);
  return !text;
}
function toast(text, type = 'ok') {
  const t = document.createElement('div');
  t.className = 'toast ' + (type === 'err' ? 'err' : '');
  t.textContent = text;
  $('toasts').appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 300); }, 3200);
}

/* ---------- Theme ---------- */
const theme = {
  init() {
    const saved = Store.get('habalgo:theme', null);
    document.documentElement.dataset.theme = saved || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  },
  toggle() {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    Store.set('habalgo:theme', next);
  }
};

/* ---------- Lockout countdown ---------- */
let lockTimer = null;
function refreshLock() {
  clearInterval(lockTimer);
  const btn = $('loginBtn');
  const tick = () => {
    const left = AuthService.lockLeft();
    if (left > 0) {
      btn.disabled = true; btn.textContent = `Locked · try again in ${left}s`;
      flash('err', 'Too many failed attempts. Please wait before trying again.');
    } else {
      clearInterval(lockTimer); btn.disabled = false; btn.textContent = 'Log in';
      if ($('msg').textContent.startsWith('Too many')) clearFlash();
    }
  };
  if (AuthService.lockLeft() > 0) { tick(); lockTimer = setInterval(tick, 1000); }
}

/* ---------- Inactivity auto logout ---------- */
let idleTimer = null;
function resetIdle() {
  clearTimeout(idleTimer);
  if (!AuthService.current()) return;
  idleTimer = setTimeout(() => {
    AuthService.logout(); location.hash = '#login'; route();
    toast('You were logged out after 15 minutes of inactivity.', 'err');
  }, IDLE_MS);
}
['click', 'keydown', 'pointermove', 'touchstart'].forEach(ev => document.addEventListener(ev, resetIdle, { passive: true }));

/* ---------- Router (#home #login #dashboard) ---------- */
const views = { home: $('view-home'), login: $('view-login'), dash: $('view-dash') };
function showView(name) {
  Object.entries(views).forEach(([k, el]) => el.classList.toggle('active', k === name));
  window.scrollTo({ top: 0 });
}
function route() {
  const page = location.hash.slice(1) || 'home';
  const user = AuthService.current();
  $('navLogin').hidden = !!user;
  $('navDash').hidden = !user;

  if (page === 'dashboard') {
    if (!user) { location.hash = '#login'; return; }
    renderDashboard(user); showView('dash');
  } else if (page === 'login') {
    if (user) { location.hash = '#dashboard'; return; }
    showView('login'); refreshLock();
  } else {
    showView('home');
  }
  resetIdle();
}
function renderDashboard(u) {
  const h = new Date().getHours();
  const ok = u.status === 'verified';
  $('dGreet').textContent = h < 12 ? 'Good morning,' : h < 18 ? 'Good afternoon,' : 'Good evening,';
  $('dName').textContent = u.name;
  $('dId').textContent = u.riderId;
  $('dEmail').textContent = u.email;
  $('dBadge').textContent = ok ? '✓ Verified Rider' : 'Pending verification';
  $('dBadge').classList.toggle('ok', ok);
  $('dStatus').textContent = ok ? 'Your account is verified. You are ready to ride.' : 'Your details are awaiting verification.';
}

/* ---------- Events ---------- */
window.addEventListener('hashchange', route);
$('themeBtn').addEventListener('click', theme.toggle);

$('eye').addEventListener('click', () => {
  const p = $('password'), hide = p.type === 'password';
  p.type = hide ? 'text' : 'password'; $('eye').textContent = hide ? 'Hide' : 'Show';
});

// Live validation
$('email').addEventListener('input', e => { clearFlash(); setErr('email', e.target.value ? Validate.email(e.target.value) : ''); });
$('password').addEventListener('input', e => { clearFlash(); setErr('password', e.target.value ? Validate.password(e.target.value) : ''); });

// Caps Lock warning
['keydown', 'keyup'].forEach(ev => $('password').addEventListener(ev, e => {
  const on = e.getModifierState && e.getModifierState('CapsLock');
  const h = $('capsHint'); h.style.display = on ? 'block' : 'none'; h.textContent = on ? '⚠ Caps Lock is on' : '';
}));

// Demo account buttons
document.querySelectorAll('.demo-item').forEach(b => b.addEventListener('click', () => {
  $('email').value = b.dataset.email; $('password').value = b.dataset.pass;
  setErr('email', ''); setErr('password', ''); clearFlash();
}));

$('loginForm').addEventListener('submit', async e => {
  e.preventDefault(); clearFlash();
  if (AuthService.lockLeft() > 0) return refreshLock();
  const email = $('email').value, pw = $('password').value;
  const ok = [setErr('email', Validate.email(email)), setErr('password', Validate.password(pw))].every(Boolean);
  if (!ok) return;

  const btn = $('loginBtn');
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span>Logging in…';
  await new Promise(r => setTimeout(r, 500)); // small delay so the loading state is visible
  const r = await AuthService.login(email, pw, $('remember').checked);
  btn.disabled = false; btn.textContent = 'Log in';

  if (r.locked) return refreshLock();
  if (!r.ok) { flash('err', r.error); return toast(r.error, 'err'); }

  e.target.reset(); $('capsHint').style.display = 'none';
  const user = AuthService.current();
  toast(`Welcome back, ${user.name.split(' ')[0]}!`);
  location.hash = '#dashboard'; route();
});

$('logoutBtn').addEventListener('click', () => {
  AuthService.logout(); location.hash = '#login'; route();
  toast('You have been logged out.');
});

/* ---------- Cursor glow on cards + scroll reveal ---------- */
document.addEventListener('pointermove', e => {
  const c = e.target.closest && e.target.closest('.card'); if (!c) return;
  const r = c.getBoundingClientRect();
  c.style.setProperty('--mx', (e.clientX - r.left) + 'px');
  c.style.setProperty('--my', (e.clientY - r.top) + 'px');
});
const io = 'IntersectionObserver' in window
  ? new IntersectionObserver(es => es.forEach(x => { if (x.isIntersecting) { x.target.classList.add('in'); io.unobserve(x.target); } }), { threshold: .12 })
  : null;
document.querySelectorAll('.reveal').forEach(el => io ? io.observe(el) : el.classList.add('in'));

/* ---------- Init ---------- */
$('year').textContent = new Date().getFullYear();
theme.init();
route();
