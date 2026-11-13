// A complete migration, driven through the real interface by Chrome's
// DevTools Protocol virtual authenticator (WebAuthn domain). This is the
// automated check for the screens and the hosted flow: it clicks what a
// person would click, and the passkey prompts are answered by a CTAP2
// virtual authenticator instead of a finger.
//
// It is NOT a real-device run and must never be reported as one.
//
//   THINE_URL=http://localhost:8080 node run.mjs
//
// Exits non-zero unless the run ends on the migrated authority view with two
// removed rows, each carrying the transaction hash the server verified.

import puppeteer from 'puppeteer-core';

const URL = process.env.THINE_URL || 'http://localhost:8080';
const CHROME = process.env.CHROME_PATH
  || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const step = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

function fail(msg) {
  console.error('FAILED:', msg);
  process.exit(1);
}

// Wait until a visible, enabled button with this exact text exists, then
// click it. The screens disable every control while a transaction is in
// flight, so a bare click races the re-enable.
async function clickText(page, selector, text, timeout = 120000) {
  await page.waitForFunction((sel, t) => {
    const el = [...document.querySelectorAll(sel)]
      .find(b => b.textContent.trim() === t && !b.disabled && b.offsetParent !== null);
    if (!el) return false;
    el.click();
    return true;
  }, { timeout }, selector, text);
}

async function waitNotice(page, id, contains, timeout = 90000) {
  await page.waitForFunction(
    (i, c) => document.getElementById(i)?.textContent.includes(c),
    { timeout }, id, contains,
  );
}

async function activeScreen(page) {
  return page.evaluate(() =>
    document.querySelector('section[data-screen].active')?.dataset.screen);
}

async function waitScreen(page, name, timeout = 120000) {
  await page.waitForFunction(
    n => document.querySelector('section[data-screen].active')?.dataset.screen === n,
    { timeout }, name,
  );
}

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: 'new',
  protocolTimeout: 420000,
  args: ['--no-first-run', '--no-default-browser-check'],
});

try {
  const page = await browser.newPage();
  page.on('console', m => {
    if (m.type() === 'error') step('console error:', m.text().slice(0, 200));
  });

  // The virtual authenticator: CTAP2, internal transport, user verification
  // on and automatically granted, presence simulated. This is what stands in
  // for the finger.
  const cdp = await page.createCDPSession();
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  step('virtual authenticator', authenticatorId);

  await page.goto(URL, { waitUntil: 'networkidle2' });
  step('opened', URL);

  // --- Screen 1: a demo account to migrate ---
  await page.waitForFunction(() => window.__thine?.meta, { timeout: 30000 });
  const meta = await page.evaluate(() => window.__thine.meta);
  step('server network:', meta.network, 'demo:', meta.demo);

  // Demo mode opens a throwaway session; fixed mode boots straight onto the
  // pre-existing account named on the server's command line.
  if (meta.demo) {
    await page.waitForSelector('#open-session', { visible: true });
    await page.click('#open-session');
  }
  await waitScreen(page, 'authority');
  const account = await page.evaluate(() => window.__thine.own);
  step(meta.demo ? 'demo account:' : 'fixed account:', account);

  await page.waitForFunction(
    () => window.__thine.report?.authority?.stage?.stage === 'seed_controlled',
    { timeout: 60000 });

  if (meta.demo) {
    // The demo account's key derives from a seed phrase, and before migration
    // the chain accepts what that phrase signs. Prove it, so the refusal at
    // the end means something. A fixed account's phrase never reaches the
    // server, so there its beats run outside this script.
    await page.waitForSelector('#auth-seed-try', { visible: true });
    await clickText(page, '#auth-seed-try', 'Try the seed phrase');
    await waitNotice(page, 'auth-seed-result', 'accepted a transaction', 180000);
    step('seed phrase accepted before migration, as it should be');
  }

  // --- Change the lock: runs step 1, lands on the create screen ---
  await page.click('#auth-change');
  await waitScreen(page, 'create', 180000);
  step('step 1 done; creating passkey A');

  // --- Screen 3 twice, registering each on screen 4 ---
  for (const name of ['virtual passkey A', 'virtual passkey B']) {
    await page.evaluate(() => { document.getElementById('create-name').value = ''; });
    await page.type('#create-name', name);
    await page.click('#create-go');
    await waitNotice(page, 'create-notice', 'Passkey created.');
    const addr = await page.evaluate(() =>
      document.getElementById('create-address').textContent.trim());
    step(`created ${name} ->`, addr);
    await page.click('#create-continue');
    await waitScreen(page, 'register');

    // Register the one unregistered row.
    await clickText(page, '#register-rows button', 'Register');
    await page.waitForFunction(() => {
      const rows = window.__thine.passkeys;
      return rows.length && rows.filter(p => !p.registered).length === 0;
    }, { timeout: 240000 });
    step(`registered ${name}`);

    const registered = await page.evaluate(() =>
      window.__thine.passkeys.filter(p => p.registered).length);
    if (registered < 2) {
      await clickText(page, '#register-another', 'Register another passkey');
      await waitScreen(page, 'create');
    }
  }

  // --- The structural refusal is real: Continue with... both registered now,
  // so prove. First check the under-two line fired earlier is not needed;
  // instead verify the prove gate. ---
  await clickText(page, '.actions button', 'Continue');
  await waitScreen(page, 'prove');

  // Continue before proving must refuse, naming the rows.
  await clickText(page, '#prove-continue', 'Continue');
  await waitNotice(page, 'prove-notice', 'Every passkey has to sign once');
  step('prove gate refused as built');

  // --- Screen 5: prove each one ---
  for (let i = 0; i < 2; i++) {
    await clickText(page, '#prove-rows button', 'Prove this one');
    await page.waitForFunction(n => {
      const unproven = window.__thine.passkeys.filter(p => p.registered && !p.proven).length;
      return unproven === n;
    }, { timeout: 240000 }, 1 - i);
    step(`proved passkey ${i + 1}`);
  }
  await clickText(page, '#prove-continue', 'Continue');
  await waitScreen(page, 'final');

  // --- Screen 6: the two parts in order ---
  await clickText(page, '#final-self-hold', 'Remove the self hold');
  await page.waitForFunction(
    () => !document.getElementById('final-part2').hidden,
    { timeout: 240000 });
  step('self hold removed; part two visible');

  // The typed confirmation must be exact: a wrong value refuses.
  await page.type('#final-confirm', 'not-the-account');
  await clickText(page, '#final-remove', 'Remove last key');
  await waitNotice(page, 'final-notice', 'exactly as shown');
  step('typed confirmation refused a mismatch as built');

  await page.evaluate(() => { document.getElementById('final-confirm').value = ''; });
  await page.type('#final-confirm', account);
  await clickText(page, '#final-remove', 'Remove last key');
  await waitScreen(page, 'authority', 300000);

  // --- Screen 7: the migrated view, removed rows from chain evidence ---
  await page.waitForFunction(
    () => window.__thine.report?.authority?.stage?.stage === 'passkey_controlled',
    { timeout: 120000 });

  // The removal rows render only once the chain corroborates each removal,
  // and a replica can lag a just-sent transaction by a few seconds; a person
  // would refresh, so the script does.
  for (let i = 0; i < 12; i++) {
    const removed = await page.evaluate(() =>
      window.__thine.report.authority.holders.filter(h => h.status.status === 'removed').length);
    if (removed >= 2) break;
    step(`removed rows at ${removed}; refreshing`);
    await new Promise(r => setTimeout(r, 5000));
    await page.reload({ waitUntil: 'networkidle2' });
    await page.waitForFunction(
      () => window.__thine?.report?.authority?.stage?.stage === 'passkey_controlled',
      { timeout: 120000 });
  }

  // And now the same phrase against the same chain, after.
  let seedVerdict = null;
  if (meta.demo) {
    await clickText(page, '#auth-seed-try', 'Try the seed phrase');
    await waitNotice(page, 'auth-seed-result', 'refused', 240000);
    seedVerdict = await page.evaluate(() =>
      document.getElementById('auth-seed-result').textContent);
    step('seed phrase refused after migration');
  }

  const result = await page.evaluate(() => {
    const r = window.__thine.report;
    const removed = r.authority.holders
      .filter(h => h.status.status === 'removed')
      .map(h => ({ kind: h.kind.kind, tx: h.status.tx_hash }));
    const gone = [...document.querySelectorAll('.key-row.gone')].length;
    const standing = !document.getElementById('auth-standing').hidden;
    return {
      account: window.__thine.own,
      stage: r.authority.stage.stage,
      proven: r.summary.passkeys_proven,
      hasKey: r.summary.has_full_access_key,
      removed, gone, standing,
      txs: window.__thine.txs,
    };
  });
  result.seedVerdict = seedVerdict;

  if (result.stage !== 'passkey_controlled') fail(`stage is ${result.stage}`);
  if (result.hasKey) fail('a full access key remains');
  if (result.proven !== 2) fail(`proven = ${result.proven}`);
  if (result.removed.length !== 2) fail(`removed rows = ${result.removed.length}`);
  if (result.gone < 2) fail(`gone rows rendered = ${result.gone}`);
  if (!result.standing) fail('standing lines not shown on the migrated view');
  for (const r of result.removed) {
    if (!r.tx || r.tx.length < 30) fail(`removed ${r.kind} carries no transaction hash`);
  }

  console.log('\n=== MIGRATION COMPLETE (virtual authenticator, not a real device) ===');
  console.log(JSON.stringify(result, null, 2));
} finally {
  await browser.close();
}
