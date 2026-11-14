// Thine's behaviour. Structure and copy are in index.html; every visual value
// is in tokens.css. This file holds state, the WebAuthn calls, and the wiring
// to the API, and makes no visual decisions.

'use strict';

// ---------------------------------------------------------------------------
// Encoding. WebAuthn speaks ArrayBuffer; the API speaks base64url.
// ---------------------------------------------------------------------------
const b64u = {
  encode(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  decode(str) {
    const p = str.replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(p + '='.repeat((4 - p.length % 4) % 4));
    return Uint8Array.from(raw, c => c.charCodeAt(0));
  },
};

const $ = id => document.getElementById(id);

function truncMiddle(s, head = 12, tail = 6) {
  return s.length <= head + tail + 1 ? s : `${s.slice(0, head)}…${s.slice(-tail)}`;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const S = {
  meta: null,
  token: null,
  own: null,       // the session's own, migratable account
  viewing: null,   // the account the authority screen shows
  report: null,
  passkeys: [],    // [{name, credentialId, publicKey, accountId, registered, proven, provenAt}]
  seedPhrase: null,
  txs: [],         // every transaction hash observed, oldest first
};
window.__thine = S;

function saveLocal() {
  try {
    if (S.token) localStorage.setItem('thine.session',
      JSON.stringify({ token: S.token, own: S.own, seedPhrase: S.seedPhrase }));
    if (S.own) localStorage.setItem(`thine.passkeys.${S.own}`, JSON.stringify(S.passkeys));
  } catch {}
}
function loadLocal() {
  try {
    const sess = JSON.parse(localStorage.getItem('thine.session') || 'null');
    if (sess) { S.token = sess.token; S.own = sess.own; S.seedPhrase = sess.seedPhrase || null; }
    if (S.own) S.passkeys = JSON.parse(localStorage.getItem(`thine.passkeys.${S.own}`) || '[]');
  } catch {}
}

async function api(path, body) {
  const headers = { 'content-type': 'application/json' };
  if (S.token) headers['x-thine-session'] = S.token;
  const res = await fetch(path, body === undefined
    ? { headers }
    : { method: 'POST', headers, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `${path} failed with ${res.status}`);
    err.status = res.status;
    throw err;
  }
  recordTxs(data);
  return data;
}

function recordTxs(data) {
  if (!data) return;
  if (typeof data.tx_hash === 'string') S.txs.push(data.tx_hash);
  if (Array.isArray(data.steps)) for (const s of data.steps) if (s.tx_hash) S.txs.push(s.tx_hash);
}

function show(name) {
  for (const el of document.querySelectorAll('section[data-screen]')) {
    el.classList.toggle('active', el.dataset.screen === name);
  }
}

function busy(ruleId, actionsId, on) {
  // In flight, the action is replaced in place by the 1px indeterminate rule.
  $(ruleId).hidden = !on;
  if (actionsId) $(actionsId).style.display = on ? 'none' : '';
  for (const b of document.querySelectorAll('button')) b.disabled = on;
}

document.addEventListener('click', async e => {
  const btn = e.target.closest('button[data-copy]');
  if (!btn) return;
  const value = document.querySelector(btn.dataset.copy)?.textContent?.trim();
  if (value) { try { await navigator.clipboard.writeText(value); } catch {} }
});

// ---------------------------------------------------------------------------
// Rendering: the key row component
// ---------------------------------------------------------------------------
function holderRow(h) {
  const row = document.createElement('div');
  row.className = 'key-row';
  const removed = h.status.status === 'removed';
  if (removed) row.classList.add('gone');

  // Authority is encoded as fill density: solid for full access, hatched for
  // an extension, outlined for a scoped key, faded once gone.
  const kind = h.kind.kind;
  let value, badge, treatment, capability;
  if (kind === 'full_access_key') {
    value = h.kind.public_key;
    badge = 'Full access';
    treatment = 'badge--full';
    capability = 'Can do anything, including delete this account';
  } else if (kind === 'function_call_key') {
    value = h.kind.public_key;
    badge = 'Function call key';
    treatment = 'badge--scoped';
    capability = 'Calls named methods on one contract, nothing else';
  } else if (kind === 'self_extension') {
    value = S.viewing || '';
    badge = 'Extension';
    treatment = 'badge--extension';
    capability = 'The account signing for itself; removed at the end of migration';
  } else {
    value = h.kind.account_id;
    badge = 'Extension';
    treatment = 'badge--extension';
    capability = 'Signs for this account through a passkey';
  }
  if (removed) treatment = 'badge--gone';

  const head = document.createElement('div');
  head.className = 'row-head';
  const v = document.createElement('span');
  v.className = 'value';
  // Middle truncation; the full value is a tap away.
  v.textContent = truncMiddle(value, 16, 8);
  v.title = value;
  v.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(value); } catch {}
  });
  const b = document.createElement('span');
  b.className = `badge ${treatment}`;
  if (treatment === 'badge--extension') {
    // The label knocks out of the hatch on a surface plate.
    const k = document.createElement('span');
    k.className = 'knockout';
    k.textContent = badge;
    b.append(k);
  } else {
    b.textContent = badge;
  }
  head.append(v, b);
  row.append(head);

  if (removed) {
    // The removal renders from the fetched transaction, never from memory:
    // the hash is there so a reader checks it against the chain.
    const field = document.createElement('div');
    field.className = 'copy-field';
    const code = document.createElement('code');
    code.textContent = h.status.tx_hash;
    const copy = document.createElement('button');
    copy.textContent = 'Copy';
    copy.dataset.copy = `#noop`;
    copy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(h.status.tx_hash); } catch {}
    });
    field.append(code, copy);
    row.append(field);
  } else {
    const cap = document.createElement('div');
    cap.className = 'capability';
    let note = capability;
    if (h.status.status === 'unreachable') note = `UNREACHABLE: ${h.status.reason}`;
    cap.textContent = note;
    row.append(cap);
  }
  return row;
}

function controlLine(stage) {
  if (stage === 'seed_controlled')
    return 'Opened by a seed phrase. Anyone holding those words holds the account.';
  if (stage === 'wallet_deployed')
    return 'Opened by its keys, through a wallet contract that delegates to itself.';
  if (stage === 'passkeys_added')
    return 'Opened by its keys and by the passkeys it has registered.';
  return 'Opened by your passkeys. The account id, the balance, the staking and the history are the same as before.';
}

// ---------------------------------------------------------------------------
// Screens 2 and 7: the authority view
// ---------------------------------------------------------------------------
async function openAuthority(accountId) {
  S.viewing = accountId;
  show('authority');
  $('auth-id').textContent = accountId;
  $('auth-control-line').textContent = '';
  $('auth-notice').textContent = '';
  const rows = $('auth-rows');
  rows.textContent = '';
  // Rows arrive as the read returns; there is no fixed skeleton.
  const loading = document.createElement('div');
  loading.className = 'rule-indeterminate';
  rows.append(loading);

  try {
    S.report = accountId === S.own && S.token
      ? await api('/api/account')
      : await api(`/api/inspect/${accountId}`);
  } catch (e) {
    rows.textContent = '';
    $('auth-notice').textContent = e.message;
    return;
  }
  renderAuthority();
}

function renderAuthority() {
  const r = S.report;
  const stage = r.authority.stage.stage;
  const own = S.viewing === S.own && !!S.token;
  const migrated = stage === 'passkey_controlled';

  $('auth-control-line').textContent = controlLine(stage);

  const rows = $('auth-rows');
  rows.textContent = '';
  if (r.authority.holders.length === 0) {
    const p = document.createElement('p');
    p.className = 'graphite';
    p.textContent = 'Nobody. This account has no keys and no reachable delegates.';
    rows.append(p);
  }
  for (const h of r.authority.holders) rows.append(holderRow(h));

  // Standing properties of a migrated account; final state only.
  $('auth-standing').hidden = !migrated;

  $('auth-orphaned').textContent = r.orphaned
    ? `This account also pays for ${r.orphaned.bytes} bytes of storage nothing can read any more `
      + `(${r.orphaned.staked.near.toFixed(6)} NEAR, staked permanently).`
    : '';

  // The demo's seed phrase, and the button that asks the chain about it.
  const showSeed = own && !!S.seedPhrase;
  $('auth-seed').hidden = !showSeed;
  if (showSeed) $('auth-seed-words').textContent = S.seedPhrase;

  $('auth-change').hidden = migrated;
  $('auth-stay-line').hidden = migrated;
  $('auth-register-another').hidden = !(migrated && own);
  $('auth-copy').hidden = !migrated;
  $('auth-copy-value').textContent = S.viewing;

  syncPasskeysFromReport();
  saveLocal();
}

function syncPasskeysFromReport() {
  if (!S.report || S.viewing !== S.own) return;
  const holders = S.report.authority.holders;
  for (const p of S.passkeys) {
    const h = holders.find(x => x.kind.kind === 'passkey_extension' && x.kind.account_id === p.accountId);
    if (h) {
      p.registered = true;
      if (h.status.status === 'proven') p.proven = true;
    }
  }
}

$('auth-back').addEventListener('click', () => show('open'));

$('auth-change').addEventListener('click', async () => {
  const own = S.viewing === S.own && !!S.token;
  if (!own) {
    $('auth-notice').textContent =
      'This demo migrates its own throwaway account. Create one on the start screen.';
    return;
  }
  const current = S.report.plan.steps[S.report.plan.current]?.id;
  try {
    if (current === 'become-wallet') {
      busy('open-rule', null, false);
      $('auth-notice').textContent = '';
      for (const b of document.querySelectorAll('button')) b.disabled = true;
      await api('/api/step1', {});
      S.report = await api('/api/account');
      for (const b of document.querySelectorAll('button')) b.disabled = false;
      show('create');
    } else if (current === 'add-passkeys') {
      show(S.passkeys.length ? 'register' : 'create');
      renderRegister();
    } else if (current === 'prove-passkeys') {
      show('prove');
      renderProve();
    } else {
      show('final');
      renderFinal();
    }
  } catch (e) {
    for (const b of document.querySelectorAll('button')) b.disabled = false;
    $('auth-notice').textContent = e.message;
  }
});

$('auth-seed-try').addEventListener('click', async () => {
  $('auth-seed-result').textContent = '';
  const btn = $('auth-seed-try');
  btn.disabled = true;
  try {
    const out = await api('/api/try-seed', {});
    // The chain's own words, never paraphrased.
    $('auth-seed-result').textContent = out.accepted
      ? `The chain accepted a transaction signed with the phrase. Tx ${out.detail}`
      : `The chain refused it: ${out.detail}`;
  } catch (e) {
    $('auth-seed-result').textContent = e.message;
  } finally {
    btn.disabled = false;
  }
});

$('auth-register-another').addEventListener('click', () => {
  $('auth-notice').textContent =
    'Registering after migration routes through an existing passkey, which this demo has not wired yet.';
});

// ---------------------------------------------------------------------------
// Screen 1: open an account
// ---------------------------------------------------------------------------
$('open-go').addEventListener('click', async () => {
  const id = $('open-input').value.trim();
  if (!id) return;
  $('open-notice').textContent = '';
  // Reading: the action is replaced in place; the input is not disabled.
  $('open-actions').style.display = 'none';
  $('open-rule').hidden = false;
  try {
    await api(`/api/inspect/${id}`);
    await openAuthority(id);
  } catch (e) {
    $('open-notice').textContent = e.status === 404
      ? `No account with that id exists on ${S.meta.network}.`
      : e.message;
  } finally {
    $('open-actions').style.display = '';
    $('open-rule').hidden = true;
  }
});

$('open-session').addEventListener('click', async () => {
  $('open-notice').textContent = '';
  $('open-actions').style.display = 'none';
  $('open-rule').hidden = false;
  try {
    const out = await api('/api/session', {});
    S.token = out.token;
    S.own = out.account_id;
    S.seedPhrase = out.seed_phrase || null;
    S.passkeys = [];
    saveLocal();
    await openAuthority(S.own);
  } catch (e) {
    $('open-notice').textContent = e.message;
  } finally {
    $('open-actions').style.display = '';
    $('open-rule').hidden = true;
  }
});

// ---------------------------------------------------------------------------
// Screen 3: create the passkey
// ---------------------------------------------------------------------------
$('create-back').addEventListener('click', () => openAuthority(S.own));
$('create-continue').addEventListener('click', () => { show('register'); renderRegister(); });

$('create-go').addEventListener('click', async () => {
  $('create-notice').textContent = '';
  if (!window.PublicKeyCredential) {
    $('create-notice').textContent = 'This browser has no WebAuthn. A passkey needs it.';
    return;
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(location.hostname)) {
    $('create-notice').textContent =
      `Passkeys will not work on ${location.hostname}: an IP address cannot be a WebAuthn ` +
      `relying party. Open this page on http://localhost:${location.port} instead.`;
    return;
  }

  // The device's own sheet is the operating system: while it is open the
  // screen shows the rule and nothing narrates what the sheet is doing.
  busy('create-rule', 'create-actions', true);
  let created;
  try {
    created = await navigator.credentials.create({
      publicKey: {
        // Registration is not verified on chain: only the public key is taken
        // from it, so this challenge is not a security boundary.
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: 'Thine' },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: S.own,
          displayName: S.own,
        },
        // ES256 only: the contract verifies P-256 and nothing else.
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { userVerification: 'preferred', residentKey: 'preferred' },
        timeout: 120000,
      },
    });
  } catch {
    busy('create-rule', 'create-actions', false);
    $('create-notice').textContent = 'No passkey was created. Nothing has changed.';
    return;
  }

  try {
    const spki = created.response.getPublicKey();
    if (!spki) throw new Error('This authenticator did not report a public key.');
    const publicKey = b64u.encode(spki);
    const derived = await api('/api/passkey/derive', { public_key: publicKey });

    $('create-address').textContent = derived.account_id;
    S.passkeys.push({
      name: $('create-name').value.trim() || 'this device',
      credentialId: b64u.encode(created.rawId),
      publicKey,
      accountId: derived.account_id,
      registered: false,
      proven: false,
      provenAt: null,
    });
    saveLocal();
    $('create-notice').textContent = 'Passkey created.';
    $('create-continue').hidden = false;
  } catch (e) {
    $('create-notice').textContent = e.message;
  } finally {
    busy('create-rule', 'create-actions', false);
  }
});

// ---------------------------------------------------------------------------
// Signing: ask the device, submit the assertion
// ---------------------------------------------------------------------------
async function sign(passkey, purpose) {
  const begun = await api('/api/passkey/begin', { public_key: passkey.publicKey, purpose });
  const got = await navigator.credentials.get({
    publicKey: {
      challenge: b64u.decode(begun.challenge),
      allowCredentials: [{ type: 'public-key', id: b64u.decode(passkey.credentialId) }],
      userVerification: 'preferred',
      timeout: 120000,
    },
  });
  return api('/api/passkey/finish', {
    token: begun.token,
    authenticator_data: b64u.encode(got.response.authenticatorData),
    // The exact bytes as text: hashed byte-for-byte on chain, so
    // re-serialising the JSON would invalidate the signature.
    client_data_json: new TextDecoder().decode(got.response.clientDataJSON),
    signature: b64u.encode(got.response.signature),
  });
}

// ---------------------------------------------------------------------------
// Screen 4: register
// ---------------------------------------------------------------------------
function renderRegister() {
  const rows = $('register-rows');
  rows.textContent = '';
  for (const p of S.passkeys) {
    const row = document.createElement('div');
    row.className = 'key-row';
    const head = document.createElement('div');
    head.className = 'row-head';
    const v = document.createElement('span');
    v.className = 'value';
    v.textContent = `${p.name}  ${truncMiddle(p.publicKey, 12, 6)}`;
    const b = document.createElement('span');
    b.className = 'row-state';
    head.append(v, b);
    row.append(head);
    if (p.registered) {
      b.textContent = 'Registered';
    } else {
      const act = document.createElement('button');
      act.textContent = 'Register';
      act.addEventListener('click', () => registerOne(p));
      b.textContent = '';
      b.append(act);
    }
    rows.append(row);
  }
}

async function registerOne(p) {
  $('register-notice').textContent = '';
  busy('register-rule', null, true);
  try {
    // Create the 0s account, signed directly by the passkey, then authorise
    // it as an extension.
    await sign(p, 'create');
    await api('/api/step3', { account_id: p.accountId });
    p.registered = true;
    saveLocal();
    S.report = await api('/api/account');
    renderRegister();
  } catch (e) {
    $('register-notice').textContent = e.message;
  } finally {
    busy('register-rule', null, false);
    renderRegister();
  }
}

$('register-another').addEventListener('click', () => show('create'));
$('register-continue').addEventListener('click', () => {
  const registered = S.passkeys.filter(p => p.registered).length;
  if (registered < 2) {
    // The requirement lives in the control: never greyed out, because a
    // disabled control explains nothing.
    $('register-notice').textContent =
      'Register a second passkey first. One device is one way to lose the account.';
    return;
  }
  show('prove');
  renderProve();
});

// ---------------------------------------------------------------------------
// Screen 5: prove
// ---------------------------------------------------------------------------
function renderProve() {
  const rows = $('prove-rows');
  rows.textContent = '';
  for (const p of S.passkeys.filter(p => p.registered)) {
    const row = document.createElement('div');
    row.className = 'key-row';
    const head = document.createElement('div');
    head.className = 'row-head';
    const v = document.createElement('span');
    v.className = 'value';
    v.textContent = `${p.name}  ${truncMiddle(p.publicKey, 12, 6)}`;
    const b = document.createElement('span');
    b.className = 'row-state';
    head.append(v, b);
    row.append(head);
    if (p.proven) {
      b.textContent = p.provenAt ? `Proven ${p.provenAt.replace('T', ' ').slice(0, 19)} UTC` : 'Proven';
    } else {
      const act = document.createElement('button');
      act.textContent = 'Prove this one';
      act.addEventListener('click', () => proveOne(p));
      b.append(act);
    }
    rows.append(row);
  }
}

async function proveOne(p) {
  $('prove-notice').textContent = '';
  busy('prove-rule', null, true);
  try {
    await sign(p, 'prove');
    p.proven = true;
    p.provenAt = new Date().toISOString();
    saveLocal();
    S.report = await api('/api/account');
  } catch (e) {
    $('prove-notice').textContent = e.message;
  } finally {
    busy('prove-rule', null, false);
    renderProve();
  }
}

$('prove-continue').addEventListener('click', () => {
  const unproven = S.passkeys.filter(p => p.registered && !p.proven);
  if (unproven.length) {
    $('prove-notice').textContent =
      `Every passkey has to sign once before the next step. Unproven: ${unproven.map(p => p.name).join(', ')}.`;
    return;
  }
  show('final');
  renderFinal();
});

// ---------------------------------------------------------------------------
// Screen 6: the point of no return
// ---------------------------------------------------------------------------
async function renderFinal() {
  $('final-notice').textContent = '';
  $('final-part1-rows').textContent = '';
  const selfRemoved = S.report.authority.holders.some(
    h => h.kind.kind === 'self_extension' && h.status.status === 'removed');
  // Once done, the row for that extension moves to the Gone treatment and
  // stays visible.
  for (const h of S.report.authority.holders) {
    if (h.kind.kind === 'self_extension') $('final-part1-rows').append(holderRow(h));
  }
  $('final-self-hold').disabled = selfRemoved;
  $('final-part2').hidden = !selfRemoved;
  if (selfRemoved) await renderRemains();
}

async function renderRemains() {
  const remains = $('final-remains');
  remains.textContent = '';
  $('final-remains-notice').textContent = '';
  $('final-confirm').placeholder = S.own;
  try {
    // Built from a live read of the account rather than from what the
    // product intends.
    const fresh = await api('/api/account');
    S.report = fresh;
    for (const h of fresh.authority.holders) {
      const kind = h.kind.kind;
      if (h.status.status === 'removed') continue;
      if (kind === 'full_access_key' || kind === 'self_extension') continue;
      remains.append(holderRow(h));
    }
    $('final-confirm').parentElement.hidden = false;
    $('final-confirm').hidden = false;
    $('final-actions').hidden = false;
    document.querySelector('label[for="final-confirm"]').hidden = false;
  } catch {
    $('final-remains-notice').textContent =
      'The account could not be read just now, so this step is not available.';
    $('final-confirm').hidden = true;
    $('final-actions').hidden = true;
    document.querySelector('label[for="final-confirm"]').hidden = true;
  }
}

$('final-self-hold').addEventListener('click', async () => {
  $('final-notice').textContent = '';
  busy('final-rule', null, true);
  try {
    await api('/api/step5a', {});
    S.report = await api('/api/account');
    await renderFinal();
  } catch (e) {
    $('final-notice').textContent = e.message;
  } finally {
    busy('final-rule', null, false);
  }
});

$('final-back').addEventListener('click', () => openAuthority(S.own));

$('final-remove').addEventListener('click', async () => {
  $('final-notice').textContent = '';
  if ($('final-confirm').value.trim() !== S.own) {
    $('final-notice').textContent = 'Type the account id exactly as shown.';
    return;
  }
  busy('final-rule', 'final-actions', true);
  try {
    await api('/api/step5b', {});
    await openAuthority(S.own);
  } catch (e) {
    // The failure state leaves everything intact.
    $('final-notice').textContent = `${e.message} Nothing was removed.`;
  } finally {
    busy('final-rule', 'final-actions', false);
  }
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
(async function boot() {
  loadLocal();
  try {
    S.meta = await api('/api/meta');
  } catch (e) {
    $('open-notice').textContent = `Could not reach the server: ${e.message}`;
    return;
  }
  $('open-input').placeholder = S.meta.example_account;
  $('masthead-network').textContent = S.meta.network;
  $('open-demo').hidden = !S.meta.demo;

  if (!S.meta.demo) {
    // Fixed mode: the one account is the session.
    try {
      const out = await api('/api/session', {});
      S.token = out.token;
      S.own = out.account_id;
      S.passkeys = JSON.parse(localStorage.getItem(`thine.passkeys.${S.own}`) || '[]');
      await openAuthority(S.own);
      return;
    } catch {}
  } else if (S.token && S.own) {
    // A restored demo session, if the server still knows it.
    try {
      await api('/api/account');
      await openAuthority(S.own);
      return;
    } catch {
      S.token = null;
      S.own = null;
    }
  }
  show('open');
})();
