// Tests de bout en bout dans de vrais navigateurs, via l'interface.
// Le module `format` ci-dessous réimplémente le format depuis sa spécification,
// sans partager de code avec worker.js : il vérifie l'interopérabilité, et que
// le README suffit à relire un fichier sans le site.
//
// Usage : npm test
// Variables : BROWSERS=chrome,webkit,firefox  LARGE_MIB=300

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream, promises as fs } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium, firefox, webkit } from 'playwright';
import sodium from 'libsodium-wrappers-sumo';

await sodium.ready;

const PUBLIC_DIR = fileURLToPath(new URL('../public/', import.meta.url));
const MIB = 1024 * 1024;
const LARGE_MIB = Number(process.env.LARGE_MIB ?? 300);
const PASSWORD = 'correct horse battery staple';

const format = {
  HEADER: 56,
  CHUNK: MIB,
  ABYTES: 17,

  header(mode, ops, memKib, salt, streamHeader) {
    const header = Buffer.alloc(56);
    header.write('CYPH', 0, 'latin1');
    header[4] = 1;
    header[5] = mode;
    header.writeUInt32LE(ops, 8);
    header.writeUInt32LE(memKib, 12);
    salt.forEach((byte, i) => { header[16 + i] = byte; });
    streamHeader.forEach((byte, i) => { header[32 + i] = byte; });
    return header;
  },

  passwordKey(password, salt, ops, memKib) {
    return sodium.crypto_pwhash(32, Buffer.from(password.normalize('NFC')), salt, ops, memKib * 1024,
      sodium.crypto_pwhash_ALG_ARGON2ID13);
  },

  encryptWithKey(key, plain) {
    const { state, header: streamHeader } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    return this.seal(state, this.header(2, 0, 0, Buffer.alloc(16), streamHeader), plain);
  },

  // `password` n'est pas normalisé ici : le test NFD doit passer par le navigateur.
  encryptWithPassword(password, plain) {
    const salt = sodium.randombytes_buf(16);
    const key = this.passwordKey(password, salt, 3, 262144);
    const { state, header: streamHeader } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    return this.seal(state, this.header(1, 3, 262144, salt, streamHeader), plain);
  },

  seal(state, header, plain) {
    const parts = [header];
    let offset = 0;
    do {
      const end = Math.min(offset + this.CHUNK, plain.length);
      const tag = end === plain.length
        ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
      parts.push(Buffer.from(sodium.crypto_secretstream_xchacha20poly1305_push(state, plain.subarray(offset, end), header, tag)));
      offset = end;
    } while (offset < plain.length);
    return Buffer.concat(parts);
  },

  decrypt(cipher, secret) {
    const header = cipher.subarray(0, 56);
    assert.equal(header.toString('latin1', 0, 4), 'CYPH');
    assert.equal(header[4], 1);
    const key = header[5] === 1
      ? this.passwordKey(secret, header.subarray(16, 32), header.readUInt32LE(8), header.readUInt32LE(12))
      : secret;
    const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header.subarray(32, 56), key);
    const parts = [];
    let offset = 56;
    for (;;) {
      const end = Math.min(offset + this.CHUNK + this.ABYTES, cipher.length);
      const pulled = sodium.crypto_secretstream_xchacha20poly1305_pull(state, cipher.subarray(offset, end), header);
      assert.ok(pulled, 'échec du déchiffrement indépendant');
      parts.push(Buffer.from(pulled.message));
      offset = end;
      if (pulled.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) break;
      assert.ok(offset < cipher.length, 'flux tronqué');
    }
    assert.equal(offset, cipher.length);
    return Buffer.concat(parts);
  },
};

const decodeKey = (encoded) => Buffer.from(encoded, 'base64url');

const extraHeaders = {};

function serve() {
  const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' };
  const server = createServer(async (req, res) => {
    const relative = new URL(req.url, 'http://x').pathname.replace(/^\//, '') || 'index.html';
    const target = path.resolve(PUBLIC_DIR, relative);
    if (!target.startsWith(PUBLIC_DIR)) { res.writeHead(403).end(); return; }
    try {
      const body = await fs.readFile(target);
      res.writeHead(200, { ...extraHeaders, 'content-type': types[path.extname(target)] ?? 'application/octet-stream' });
      res.end(body);
    } catch {
      res.writeHead(404).end();
    }
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, base: `http://127.0.0.1:${server.address().port}/` }));
  });
}

// Pilotage de l'interface ------------------------------------------------------

async function open(context, base) {
  const page = await context.newPage();
  await page.goto(base);
  await page.waitForSelector('#form', { state: 'visible' });
  return page;
}

async function pick(page, name, content) {
  const input = typeof content === 'string'
    ? content
    : { name, mimeType: 'application/octet-stream', buffer: content };
  await page.setInputFiles('#file', input);
  await page.waitForSelector('#options', { state: 'visible' });
}

async function submit(page) {
  await page.click('#submit');
  await page.waitForSelector('#result-panel:visible, #message:visible', { timeout: 300_000 });
  const message = page.locator('#message');
  return await message.isVisible() ? { error: await message.textContent() } : { ok: true };
}

async function download(page) {
  const [event] = await Promise.all([page.waitForEvent('download'), page.click('#download')]);
  return { name: event.suggestedFilename(), bytes: await fs.readFile(await event.path()) };
}

async function clearResult(page) {
  await page.click('#reset');
  await page.waitForSelector('#dropzone-empty', { state: 'visible' });
}

async function encryptWithPassword(page, name, plain, password = PASSWORD) {
  await pick(page, name, plain);
  await page.check('input[name="action"][value="encrypt"]', { force: true });
  await page.check('input[name="method"][value="password"]', { force: true });
  await page.fill('#password', password);
  await page.fill('#confirm', password);
  const outcome = await submit(page);
  assert.ok(outcome.ok, outcome.error);
  return download(page);
}

async function encryptWithKey(page, name, plain) {
  await pick(page, name, plain);
  await page.check('input[name="method"][value="key"]', { force: true });
  await page.click('#generate-key');
  await page.waitForFunction(() => document.getElementById('key').value.length === 43);
  const key = await page.inputValue('#key');
  const outcome = await submit(page);
  assert.ok(outcome.ok, outcome.error);
  return { ...await download(page), key };
}

async function decrypt(page, name, cipher, { password, key }) {
  await pick(page, name, cipher);
  assert.equal(await page.isChecked('input[name="action"][value="decrypt"]'), true, 'fichier Cypher non détecté');
  if (password !== undefined) await page.fill('#password', password);
  if (key !== undefined) await page.fill('#key', key);
  return submit(page);
}

const opfsEntries = (page) => page.evaluate(async () => {
  const root = await navigator.storage.getDirectory();
  const names = [];
  for await (const name of root.keys()) names.push(name);
  return names;
});

async function expectRefused(page, cipher, secret, pattern) {
  const outcome = await decrypt(page, 'x.cypher', cipher, secret);
  assert.ok(outcome.error, 'le déchiffrement aurait dû être refusé');
  assert.match(outcome.error, pattern);
  assert.equal(await page.isVisible('#result-panel'), false);
  assert.deepEqual(await opfsEntries(page), [], "du clair partiel est resté dans l'OPFS");
  await page.reload();
  await page.waitForSelector('#form', { state: 'visible' });
}

async function makeLargeFile(mib) {
  const file = path.join(await fs.mkdtemp(path.join(tmpdir(), 'cypher-')), 'large.bin');
  const stream = createWriteStream(file);
  const hash = createHash('sha256');
  const block = randomBytes(MIB);
  for (let i = 0; i < mib; i++) {
    block[0] = i & 0xff; // évite que le fichier soit la répétition exacte d'un bloc
    block[1] = i >> 8;
    hash.update(block);
    if (!stream.write(block)) await new Promise((resolve) => stream.once('drain', resolve));
  }
  await new Promise((resolve) => stream.end(resolve));
  return { file, sha256: hash.digest('hex') };
}

async function sha256File(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

// Scénarios --------------------------------------------------------------------

const tests = {
  async 'mot de passe : aller-retour, tailles limites, relecture indépendante'({ page }) {
    for (const size of [0, 1, MIB - 1, MIB, MIB + 1, 2 * MIB, 3 * MIB + 12345]) {
      const plain = randomBytes(size);
      const encrypted = await encryptWithPassword(page, 'doc.pdf', plain);
      assert.equal(encrypted.name, 'doc.pdf.cypher');
      assert.ok(format.decrypt(encrypted.bytes, PASSWORD).equals(plain), `Node, taille ${size}`);
      await clearResult(page);

      const outcome = await decrypt(page, encrypted.name, encrypted.bytes, { password: PASSWORD });
      assert.ok(outcome.ok, outcome.error);
      const decrypted = await download(page);
      assert.equal(decrypted.name, 'doc.pdf');
      assert.ok(decrypted.bytes.equals(plain), `navigateur, taille ${size}`);
      await clearResult(page);
    }
  },

  async 'clé 256 bits : aller-retour et relecture indépendante'({ page }) {
    const plain = randomBytes(2 * MIB + 7);
    const encrypted = await encryptWithKey(page, 'a.bin', plain);
    assert.equal(decodeKey(encrypted.key).length, 32);
    assert.ok(format.decrypt(encrypted.bytes, decodeKey(encrypted.key)).equals(plain));
    await clearResult(page);

    assert.ok((await decrypt(page, 'a.bin.cypher', encrypted.bytes, { key: ` ${encrypted.key}\n` })).ok);
    assert.ok((await download(page)).bytes.equals(plain));
  },

  async 'fichier produit par Node déchiffré dans le navigateur'({ page }) {
    const plain = randomBytes(MIB + 99);
    const key = sodium.crypto_secretstream_xchacha20poly1305_keygen();
    const encoded = sodium.to_base64(key, sodium.base64_variants.URLSAFE_NO_PADDING);
    assert.ok((await decrypt(page, 'n.cypher', format.encryptWithKey(key, plain), { key: encoded })).ok);
    assert.ok((await download(page)).bytes.equals(plain));
  },

  async 'mot de passe accentué : NFD et NFC sont équivalents'({ page }) {
    const plain = randomBytes(100);
    const cipher = format.encryptWithPassword('crème brûlée déjà vu'.normalize('NFC'), plain);
    const outcome = await decrypt(page, 'u.cypher', cipher, { password: 'crème brûlée déjà vu'.normalize('NFD') });
    assert.ok(outcome.ok, outcome.error);
    assert.ok((await download(page)).bytes.equals(plain));
  },

  async 'mauvais secret refusé'({ page }) {
    const plain = randomBytes(1000);
    await expectRefused(page, format.encryptWithPassword(PASSWORD, plain), { password: 'mauvais mot de passe' }, /incorrect/);
    const key = sodium.crypto_secretstream_xchacha20poly1305_keygen();
    const other = sodium.to_base64(randomBytes(32), sodium.base64_variants.URLSAFE_NO_PADDING);
    await expectRefused(page, format.encryptWithKey(key, plain), { key: other }, /incorrect/);
    await expectRefused(page, format.encryptWithKey(key, plain), { key: 'abc' }, /Clé invalide/);
  },

  async 'altérations détectées, aucun clair exposé'({ page }) {
    const plain = randomBytes(3 * MIB + 500);
    const key = sodium.crypto_secretstream_xchacha20poly1305_keygen();
    const encoded = sodium.to_base64(key, sodium.base64_variants.URLSAFE_NO_PADDING);
    const cipher = format.encryptWithKey(key, plain);
    const size = MIB + format.ABYTES;
    const secret = { key: encoded };
    const flip = (offset) => { const copy = Buffer.from(cipher); copy[offset] ^= 1; return copy; };

    await expectRefused(page, flip(40), secret, /incorrect|altéré/); // en-tête de flux
    await expectRefused(page, flip(6), secret, /incorrect|altéré/); // octet réservé, couvert par l'AD
    await expectRefused(page, flip(100), secret, /incorrect|altéré/); // premier bloc
    await expectRefused(page, flip(56 + size + 100), secret, /altéré/); // bloc du milieu
    await expectRefused(page, flip(cipher.length - 1), secret, /altéré/); // tag final
    await expectRefused(page, cipher.subarray(0, 56 + 2 * size), secret, /incomplet/); // coupe entre deux blocs
    await expectRefused(page, cipher.subarray(0, 56 + size + 500), secret, /altéré/); // coupe dans un bloc
    await expectRefused(page, cipher.subarray(0, 56), secret, /incomplet/); // en-tête seul
    await expectRefused(page, Buffer.concat([cipher, Buffer.from([0])]), secret, /altéré/); // données ajoutées
    await expectRefused(page, Buffer.concat([ // deux blocs inversés
      cipher.subarray(0, 56),
      cipher.subarray(56 + size, 56 + 2 * size),
      cipher.subarray(56, 56 + size),
      cipher.subarray(56 + 2 * size),
    ]), secret, /incorrect|altéré/);
  },

  async 'en-tête forgé : paramètres Argon2id hors bornes refusés sans calcul'({ page }) {
    const forged = format.header(1, 3, 0xffffffff, Buffer.alloc(16), Buffer.alloc(24));
    const started = Date.now();
    await expectRefused(page, Buffer.concat([forged, Buffer.alloc(40)]), { password: PASSWORD }, /altéré/);
    assert.ok(Date.now() - started < 5000);
    const version = format.header(2, 0, 0, Buffer.alloc(16), Buffer.alloc(24));
    version[4] = 9;
    await expectRefused(page, Buffer.concat([version, Buffer.alloc(40)]), { key: 'a'.repeat(43) }, /plus récente/);
  },

  async 'validation du formulaire'({ page }) {
    await pick(page, 'a.txt', Buffer.from('bonjour'));
    assert.equal(await page.isDisabled('input[name="action"][value="decrypt"]'), true);
    await page.fill('#password', 'court');
    await page.fill('#confirm', 'court');
    assert.match((await submit(page)).error, /au moins 12/);
    await page.fill('#password', PASSWORD);
    await page.fill('#confirm', `${PASSWORD}x`);
    assert.match((await submit(page)).error, /ne correspondent pas/);
  },

  async 'fichiers temporaires effacés, y compris à la réouverture'({ page, context, base }) {
    await encryptWithPassword(page, 'a.txt', randomBytes(1000));
    assert.equal((await opfsEntries(page)).length, 1, "le résultat aurait dû passer par l'OPFS");
    await clearResult(page);
    assert.deepEqual(await opfsEntries(page), []);

    await encryptWithPassword(page, 'a.txt', randomBytes(1000));
    await page.close();
    const reopened = await open(context, base);
    await reopened.waitForFunction(async () => {
      const root = await navigator.storage.getDirectory();
      for await (const name of root.keys()) return false;
      return true;
    });
  },

  async "un second onglet ne détruit pas le résultat du premier"({ page, context, base }) {
    const plain = randomBytes(5000);
    await pick(page, 'a.txt', plain);
    await page.check('input[name="method"][value="key"]', { force: true });
    await page.click('#generate-key');
    await page.waitForFunction(() => document.getElementById('key').value.length === 43);
    const key = await page.inputValue('#key');
    assert.ok((await submit(page)).ok);

    const second = await open(context, base);
    await second.waitForTimeout(500);
    const { bytes } = await download(page);
    assert.ok(format.decrypt(bytes, decodeKey(key)).equals(plain));

    // Et « Effacer » supprime bien le fichier même si l'autre onglet tient le verrou.
    await second.evaluate(() => { navigator.locks.request('cypher-tmp', { mode: 'shared' }, () => new Promise(() => {})); });
    await clearResult(page);
    assert.deepEqual(await opfsEntries(page), []);
    await second.close();
  },

  async 'repli en mémoire quand l\'OPFS est refusé'({ page }) {
    await page.route('**/worker.js', async (route) => {
      const response = await route.fetch();
      const patch = "StorageManager.prototype.getDirectory = () => Promise.reject(new DOMException('refusé', 'SecurityError'));\n";
      await route.fulfill({ response, body: patch + await response.text() });
    });
    const plain = randomBytes(2 * MIB + 3);
    const encrypted = await encryptWithPassword(page, 'mem.bin', plain);
    assert.ok(format.decrypt(encrypted.bytes, PASSWORD).equals(plain));
    assert.deepEqual(await opfsEntries(page), [], "le résultat aurait dû rester en mémoire");
  },

  async 'glisser-déposer'({ page }) {
    await page.evaluate(() => {
      const transfer = new DataTransfer();
      transfer.items.add(new File(['bonjour'], 'depose.txt'));
      document.getElementById('dropzone').dispatchEvent(
        new DragEvent('drop', { dataTransfer: transfer, bubbles: true, cancelable: true }),
      );
    });
    await page.waitForSelector('#options', { state: 'visible' });
    assert.equal(await page.textContent('#file-name'), 'depose.txt');
  },

  async 'CSP recommandée dans le README, envoyée en en-tête HTTP'({ page }) {
    const readme = await fs.readFile(new URL('../README.md', import.meta.url), 'utf8');
    const policy = readme.match(/Content-Security-Policy: (.+)/)[1];
    extraHeaders['content-security-policy'] = policy;
    try {
      // Un rechargement immédiat couperait le Worker de nettoyage du démarrage,
      // ce que WebKit journalise comme une erreur, avec ou sans CSP.
      await page.waitForTimeout(1000);
      await page.reload();
      await page.waitForSelector('#form', { state: 'visible' });
      const plain = randomBytes(MIB + 5);
      const { bytes } = await encryptWithPassword(page, 'csp.bin', plain);
      assert.ok(format.decrypt(bytes, PASSWORD).equals(plain));
    } finally {
      delete extraHeaders['content-security-policy'];
    }
  },

  async 'annulation : retour au formulaire, plus de fichier temporaire'({ page, large }) {
    await pick(page, 'large.bin', large.file);
    await page.check('input[name="method"][value="key"]', { force: true });
    await page.click('#generate-key');
    await page.waitForFunction(() => document.getElementById('key').value.length === 43);
    await page.click('#submit');
    await page.waitForFunction(() => document.getElementById('progress').value > 0);
    await page.click('#cancel');
    await page.waitForSelector('#form', { state: 'visible' });
    assert.equal(await page.isVisible('#message'), false);
    await page.waitForFunction(async () => {
      const root = await navigator.storage.getDirectory();
      for await (const name of root.keys()) return false;
      return true;
    }, null, { timeout: 5000 });
  },

  async 'gros fichier : aller-retour et débit'({ page, large, log }) {
    await pick(page, 'large.bin', large.file);
    await page.check('input[name="method"][value="key"]', { force: true });
    await page.click('#generate-key');
    await page.waitForFunction(() => document.getElementById('key').value.length === 43);
    const key = await page.inputValue('#key');

    let started = Date.now();
    assert.ok((await submit(page)).ok);
    const encryptMs = Date.now() - started;
    const [encrypted] = await Promise.all([page.waitForEvent('download'), page.click('#download')]);
    const cipherPath = await encrypted.path();
    assert.equal((await fs.stat(cipherPath)).size, LARGE_MIB * MIB + LARGE_MIB * 17 + 56);
    await clearResult(page);

    await page.setInputFiles('#file', cipherPath);
    await page.waitForSelector('#options', { state: 'visible' });
    await page.fill('#key', key);
    started = Date.now();
    assert.ok((await submit(page)).ok);
    const decryptMs = Date.now() - started;
    const [decrypted] = await Promise.all([page.waitForEvent('download'), page.click('#download')]);
    assert.equal(await sha256File(await decrypted.path()), large.sha256);
    log(`${LARGE_MIB} Mio : chiffrement ${(LARGE_MIB / (encryptMs / 1000)).toFixed(0)} Mio/s, déchiffrement ${(LARGE_MIB / (decryptMs / 1000)).toFixed(0)} Mio/s`);
  },
};

// Lanceur ----------------------------------------------------------------------

// Profils persistants : les contextes éphémères de WebKit n'ont pas d'OPFS, et
// le repli en mémoire masquerait alors silencieusement le chemin principal.
const browserTypes = {
  chrome: { type: chromium, options: { channel: 'chrome' } },
  webkit: { type: webkit, options: {} },
  firefox: { type: firefox, options: {} },
};

async function newProfile(browserName) {
  const { type, options } = browserTypes[browserName];
  const dir = await fs.mkdtemp(path.join(tmpdir(), 'cypher-profile-'));
  const context = await type.launchPersistentContext(dir, { ...options, acceptDownloads: true });
  return {
    context,
    async dispose() {
      await context.close();
      await fs.rm(dir, { recursive: true, force: true });
    },
  };
}

const { server, base } = await serve();
const large = await makeLargeFile(LARGE_MIB);
let failures = 0;

for (const browserName of (process.env.BROWSERS ?? 'chrome,webkit').split(',')) {
  console.log(`\n# ${browserName}`);
  const fileProfile = await newProfile(browserName);
  console.log(`  version ${fileProfile.context.browser()?.version() ?? 'persistante'}`);
  const filePage = await fileProfile.context.newPage();
  await filePage.goto(`file://${PUBLIC_DIR}index.html`);
  await filePage.waitForTimeout(300);
  console.log(`  ${await filePage.isVisible('#boot-error') ? 'ok   ' : 'ÉCHEC'} file:// affiche le message explicatif`);
  if (!await filePage.isVisible('#boot-error')) failures++;
  await fileProfile.dispose();

  for (const [name, run] of Object.entries(tests)) {
    const { context, dispose } = await newProfile(browserName);
    const problems = [];
    const started = Date.now();
    const notes = [];
    try {
      const page = await context.newPage();
      page.on('request', (request) => {
        const url = request.url();
        if (!url.startsWith(base) && !/^(blob|data):/.test(url)) problems.push(`requête externe : ${url}`);
      });
      page.on('console', (message) => {
        if (message.type() === 'error' && !/Failed to load resource.*favicon/.test(message.text())) problems.push(`console : ${message.text()}`);
      });
      page.on('pageerror', (error) => problems.push(`exception : ${error.message}`));
      await page.goto(base);
      await page.waitForSelector('#form', { state: 'visible' });
      await run({ page, context, base, large, log: (note) => notes.push(note) });
      assert.deepEqual(problems, []);
      console.log(`  ok    ${name} (${((Date.now() - started) / 1000).toFixed(1)} s)${notes.length ? ` — ${notes.join('; ')}` : ''}`);
    } catch (error) {
      failures++;
      console.log(`  ÉCHEC ${name}\n        ${String(error.message).split('\n').slice(0, 6).join('\n        ')}`);
    }
    await dispose();
  }
}

server.close();
await fs.rm(path.dirname(large.file), { recursive: true, force: true });
console.log(failures ? `\n${failures} échec(s)` : '\nTout est passé.');
process.exit(failures ? 1 : 0);
