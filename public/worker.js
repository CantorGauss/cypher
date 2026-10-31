'use strict';

// Un Worker jetable par opération : app.js le termine dès la réponse reçue,
// ce qui libère la mémoire WASM (clé, état du flux) et rend l'annulation triviale.
importScripts('vendor/libsodium-sumo.js', 'vendor/libsodium-wrappers.js');

// Format de fichier v1, décrit dans README.md.
const MAGIC = [0x43, 0x59, 0x50, 0x48]; // "CYPH"
const VERSION = 1;
const MODE_PASSWORD = 1;
const MODE_KEY = 2;
const HEADER_SIZE = 56;
const CHUNK_SIZE = 1024 * 1024;

const KDF_OPS = 3;
const KDF_MEM_KIB = 256 * 1024;
// Bornes lues depuis un fichier non fiable : sans elles, un en-tête forgé
// pourrait réclamer des To de mémoire avant toute authentification.
const KDF_MAX_OPS = 16;
const KDF_MAX_MEM_KIB = 1024 * 1024;

const TMP_PREFIX = 'cypher-tmp-';
const MAX_IN_MEMORY = 2 * 1024 ** 3;
const PROGRESS_INTERVAL_MS = 100;

class CypherError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function deriveKeyFromPassword(password, salt, ops, memKib) {
  postMessage({ type: 'phase', phase: 'kdf' });
  // NFC : un même mot de passe accentué doit donner les mêmes octets sur tout OS.
  const passwordBytes = sodium.from_string(password.normalize('NFC'));
  try {
    return sodium.crypto_pwhash(
      sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES,
      passwordBytes,
      salt,
      ops,
      memKib * 1024,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
  } catch {
    throw new CypherError('kdf-failed');
  } finally {
    sodium.memzero(passwordBytes);
  }
}

function decodeKey(encoded) {
  let key;
  try {
    key = sodium.from_base64(encoded.trim(), sodium.base64_variants.URLSAFE_NO_PADDING);
  } catch {
    throw new CypherError('bad-key');
  }
  if (key.length !== sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES) {
    throw new CypherError('bad-key');
  }
  return key;
}

function buildHeader({ mode, ops, memKib, salt, streamHeader }) {
  const header = new Uint8Array(HEADER_SIZE);
  const view = new DataView(header.buffer);
  header.set(MAGIC, 0);
  header[4] = VERSION;
  header[5] = mode;
  view.setUint32(8, ops, true);
  view.setUint32(12, memKib, true);
  header.set(salt, 16);
  header.set(streamHeader, 32);
  return header;
}

function parseHeader(header) {
  if (header.length < HEADER_SIZE || MAGIC.some((byte, i) => header[i] !== byte)) {
    throw new CypherError('not-cypher');
  }
  if (header[4] !== VERSION) throw new CypherError('unsupported-version');

  const view = new DataView(header.buffer, header.byteOffset);
  const parsed = {
    mode: header[5],
    ops: view.getUint32(8, true),
    memKib: view.getUint32(12, true),
    salt: header.slice(16, 32),
    streamHeader: header.slice(32, 56),
  };
  const validKdf = parsed.ops >= 1 && parsed.ops <= KDF_MAX_OPS
    && parsed.memKib >= 8 && parsed.memKib <= KDF_MAX_MEM_KIB;
  if (parsed.mode !== MODE_KEY && parsed.mode !== MODE_PASSWORD) throw new CypherError('corrupted');
  if (parsed.mode === MODE_PASSWORD && !validKdf) throw new CypherError('corrupted');
  return parsed;
}

// Sortie sur l'OPFS pour traiter des fichiers plus gros que la RAM. Le navigateur
// peut la refuser (navigation privée) : on se replie alors sur un Blob en mémoire.
async function createSink(expectedSize) {
  try {
    const root = await navigator.storage.getDirectory();
    const name = TMP_PREFIX + crypto.randomUUID();
    const handle = await root.getFileHandle(name, { create: true });
    const access = await handle.createSyncAccessHandle();
    let position = 0;
    return {
      tmpName: name,
      write(chunk) {
        const written = access.write(chunk, { at: position });
        if (written !== chunk.length) throw new CypherError('no-space');
        position += written;
      },
      async finish() {
        access.flush();
        access.close();
        return handle.getFile();
      },
      async abort() {
        access.close();
        await root.removeEntry(name);
      },
    };
  } catch {
    if (expectedSize > MAX_IN_MEMORY) throw new CypherError('too-large');
    const parts = [];
    return {
      write(chunk) { parts.push(chunk); },
      async finish() { return new Blob(parts, { type: 'application/octet-stream' }); },
      async abort() { parts.length = 0; },
    };
  }
}

// Le résultat n'est remis à l'appelant qu'une fois `produce` terminé : en
// déchiffrement, aucun octet n'est donc exposé avant la vérification du tag final.
async function withSink(expectedSize, produce) {
  const sink = await createSink(expectedSize);
  try {
    await produce(sink);
    return { blob: await sink.finish(), tmpName: sink.tmpName };
  } catch (err) {
    await sink.abort().catch(() => {});
    throw err;
  }
}

function progressReporter(total) {
  let last = 0;
  postMessage({ type: 'phase', phase: 'stream' });
  return (done) => {
    const now = performance.now();
    if (done === total || now - last >= PROGRESS_INTERVAL_MS) {
      last = now;
      postMessage({ type: 'progress', done, total });
    }
  };
}

async function readRange(file, start, end) {
  return new Uint8Array(await file.slice(start, end).arrayBuffer());
}

async function encrypt({ file, secret }) {
  const isPassword = secret.kind === 'password';
  const salt = isPassword
    ? sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES)
    : new Uint8Array(sodium.crypto_pwhash_SALTBYTES);
  const key = isPassword
    ? deriveKeyFromPassword(secret.value, salt, KDF_OPS, KDF_MEM_KIB)
    : decodeKey(secret.value);

  const { state, header: streamHeader } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  sodium.memzero(key);
  const header = buildHeader({
    mode: isPassword ? MODE_PASSWORD : MODE_KEY,
    ops: isPassword ? KDF_OPS : 0,
    memKib: isPassword ? KDF_MEM_KIB : 0,
    salt,
    streamHeader,
  });

  const report = progressReporter(file.size);
  return withSink(file.size + HEADER_SIZE, async (sink) => {
    sink.write(header);
    let offset = 0;
    // do/while : un fichier vide produit quand même un bloc final authentifié.
    do {
      const end = Math.min(offset + CHUNK_SIZE, file.size);
      const tag = end === file.size
        ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
      const plain = await readRange(file, offset, end);
      sink.write(sodium.crypto_secretstream_xchacha20poly1305_push(state, plain, header, tag));
      offset = end;
      report(offset);
    } while (offset < file.size);
  });
}

async function decrypt({ file, secret }) {
  const header = await readRange(file, 0, HEADER_SIZE);
  const { mode, ops, memKib, salt, streamHeader } = parseHeader(header);

  const key = mode === MODE_PASSWORD
    ? deriveKeyFromPassword(secret.value, salt, ops, memKib)
    : decodeKey(secret.value);

  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(streamHeader, key);
  sodium.memzero(key);

  const encryptedChunkSize = CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
  const report = progressReporter(file.size);
  return withSink(file.size, async (sink) => {
    let offset = HEADER_SIZE;
    let finished = false;
    while (offset < file.size && !finished) {
      const end = Math.min(offset + encryptedChunkSize, file.size);
      const pulled = pullChunk(state, await readRange(file, offset, end), header);
      if (!pulled) {
        // Le premier bloc échoue aussi bien sur un mauvais secret que sur une altération.
        throw new CypherError(offset === HEADER_SIZE ? 'wrong-secret' : 'corrupted');
      }
      finished = pulled.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
      sink.write(pulled.message);
      offset = end;
      report(offset);
    }
    if (!finished) throw new CypherError('truncated');
    if (offset !== file.size) throw new CypherError('corrupted');
  });
}

function pullChunk(state, chunk, header) {
  try {
    return sodium.crypto_secretstream_xchacha20poly1305_pull(state, chunk, header);
  } catch {
    return false;
  }
}

// Sans `name`, balaie tous les fichiers temporaires.
async function cleanup({ name: target }) {
  let root;
  try {
    root = await navigator.storage.getDirectory();
  } catch {
    return {}; // OPFS indisponible : rien n'a pu y être écrit.
  }
  for await (const name of root.keys()) {
    if (target ? name !== target : !name.startsWith(TMP_PREFIX)) continue;
    // Peut échouer si un fichier est encore verrouillé : il partira au prochain passage.
    await root.removeEntry(name).catch(() => {});
  }
  return {};
}

function generateKey() {
  const key = sodium.crypto_secretstream_xchacha20poly1305_keygen();
  const encoded = sodium.to_base64(key, sodium.base64_variants.URLSAFE_NO_PADDING);
  sodium.memzero(key);
  return { key: encoded };
}

const operations = { encrypt, decrypt, cleanup, generateKey };

self.onmessage = async ({ data }) => {
  try {
    await sodium.ready;
    postMessage({ type: 'done', ...await operations[data.op](data) });
  } catch (err) {
    const code = err instanceof CypherError ? err.code
      : err.name === 'QuotaExceededError' ? 'no-space'
      : 'internal';
    if (code === 'internal') console.error(err);
    postMessage({ type: 'error', code });
  }
};
