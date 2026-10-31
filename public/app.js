'use strict';

const MAGIC = [0x43, 0x59, 0x50, 0x48]; // "CYPH"
const MODE_PASSWORD = 1;
const EXTENSION = '.cypher';
const MIN_PASSWORD_LENGTH = 12;
const TMP_LOCK = 'cypher-tmp';

const ERRORS = {
  'not-cypher': "Ce fichier n'a pas été chiffré avec Cypher.",
  'unsupported-version': 'Ce fichier a été créé par une version plus récente de Cypher.',
  'wrong-secret': 'Mot de passe ou clé incorrect, ou fichier altéré.',
  'corrupted': "Fichier altéré ou corrompu : l'authentification a échoué. Rien n'a été produit.",
  'truncated': "Fichier incomplet : la fin est manquante. Rien n'a été produit.",
  'bad-key': 'Clé invalide : 43 caractères attendus, tels que générés par Cypher.',
  'kdf-failed': "Mémoire insuffisante pour Argon2id (256 Mio requis). Fermez d'autres onglets puis réessayez.",
  'no-space': "Espace disque insuffisant dans le navigateur pour produire ce fichier.",
  'too-large': "Ce navigateur n'autorise pas le stockage temporaire ici (navigation privée ?). Au-delà de 2 Gio, le fichier ne tient pas en mémoire.",
  'internal': "Une erreur inattendue s'est produite. Aucun résultat n'a été produit.",
};

const $ = (id) => document.getElementById(id);
const radios = (name) => [...document.querySelectorAll(`input[name="${name}"]`)];
const radioValue = (name) => radios(name).find((radio) => radio.checked).value;
const setRadio = (name, value) => radios(name).forEach((radio) => { radio.checked = radio.value === value; });

let file = null;
let headerMethod = null; // 'password' | 'key' si `file` est un fichier Cypher
let activeJob = null;
let resultUrl = null;
let resultTmpName = null;
let releaseTmpLock = null;

function formatSize(bytes) {
  const units = ['octets', 'Ko', 'Mo', 'Go', 'To'];
  const exponent = bytes === 0 ? 0 : Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exponent;
  const formatted = new Intl.NumberFormat('fr-FR', { maximumFractionDigits: exponent ? 1 : 0 }).format(value);
  return `${formatted} ${units[exponent]}`;
}

function showMessage(text) {
  $('message').textContent = text ?? '';
  $('message').hidden = !text;
}

function outputName(name, action) {
  if (action === 'encrypt') return name + EXTENSION;
  return name.endsWith(EXTENSION) && name.length > EXTENSION.length
    ? name.slice(0, -EXTENSION.length)
    : `${name}.dechiffre`;
}

function render() {
  const action = radioValue('action');
  const decrypting = action === 'decrypt';
  const method = decrypting ? headerMethod : radioValue('method');

  $('dropzone-empty').hidden = Boolean(file);
  $('dropzone-file').hidden = !file;
  $('options').hidden = !file;
  if (file) {
    $('file-name').textContent = file.name;
    $('file-size').textContent = formatSize(file.size);
  }

  radios('action').find((radio) => radio.value === 'decrypt').disabled = !headerMethod;
  $('method-field').hidden = decrypting;
  $('password-fields').hidden = method !== 'password';
  $('key-fields').hidden = method !== 'key';
  $('confirm-field').hidden = decrypting;
  $('password-hint').hidden = decrypting;
  $('key-actions').hidden = decrypting;
  $('key-hint').hidden = decrypting;
  $('submit').textContent = decrypting ? 'Déchiffrer le fichier' : 'Chiffrer le fichier';
}

// Chaque opération a son Worker, terminé dès la réponse (voir worker.js).
function runWorker(message, onEvent) {
  return new Promise((resolve, reject) => {
    const worker = new Worker('worker.js');
    activeJob = { worker, reject };
    const settle = (settler, value) => {
      worker.terminate();
      activeJob = null;
      settler(value);
    };
    worker.onmessage = ({ data }) => {
      if (data.type === 'done') settle(resolve, data);
      else if (data.type === 'error') settle(reject, new Error(data.code));
      else onEvent?.(data);
    };
    worker.onerror = () => settle(reject, new Error('internal'));
    worker.postMessage(message);
  });
}

// Le verrou partagé protège le résultat de cet onglet : un autre onglet ne balaie
// les fichiers temporaires que s'il obtient le verrou en exclusivité.
function holdTmpLock() {
  return new Promise((acquired) => {
    const released = navigator.locks.request(TMP_LOCK, { mode: 'shared' }, () => new Promise((release) => {
      // Attendre `released` : juste après release(), le verrou est encore tenu.
      releaseTmpLock = () => { release(); return released; };
      acquired();
    }));
  });
}

function sweepTmpFiles() {
  return navigator.locks.request(TMP_LOCK, { mode: 'exclusive', ifAvailable: true }, async (lock) => {
    if (lock) await runWorker({ op: 'cleanup' });
  });
}

async function discardResult() {
  if (resultUrl) URL.revokeObjectURL(resultUrl);
  resultUrl = null;
  // Suppression ciblée : le balayage ci-dessous n'a pas lieu si un autre onglet travaille.
  if (resultTmpName) await runWorker({ op: 'cleanup', name: resultTmpName });
  resultTmpName = null;
  await releaseTmpLock?.();
  releaseTmpLock = null;
  await sweepTmpFiles();
}

function showPanel(panel) {
  $('form').hidden = panel !== 'form';
  $('progress-panel').hidden = panel !== 'progress';
  $('result-panel').hidden = panel !== 'result';
}

async function reset() {
  showPanel('form');
  await discardResult();
  file = null;
  headerMethod = null;
  $('file').value = '';
  $('password').value = '';
  $('confirm').value = '';
  $('key').value = '';
  setRadio('action', 'encrypt');
  showMessage(null);
  render();
}

async function selectFile(selected) {
  showMessage(null);
  try {
    const head = new Uint8Array(await selected.slice(0, 6).arrayBuffer());
    const isCypher = MAGIC.every((byte, i) => head[i] === byte);
    headerMethod = isCypher ? (head[5] === MODE_PASSWORD ? 'password' : 'key') : null;
    file = selected;
    setRadio('action', isCypher ? 'decrypt' : 'encrypt');
  } catch {
    file = null;
    headerMethod = null;
    showMessage('Impossible de lire ce fichier. Les dossiers ne sont pas pris en charge.');
  }
  render();
  await discardResult();
}

function collectSecret(action) {
  const method = action === 'decrypt' ? headerMethod : radioValue('method');
  if (method === 'key') {
    if (!$('key').value.trim()) return { error: 'Saisissez ou générez une clé.' };
    return { secret: { kind: 'key', value: $('key').value } };
  }

  const password = $('password').value;
  if (!password) return { error: 'Saisissez le mot de passe.' };
  if (action === 'encrypt') {
    if (password.length < MIN_PASSWORD_LENGTH) {
      return { error: `Le mot de passe doit compter au moins ${MIN_PASSWORD_LENGTH} caractères.` };
    }
    if (password !== $('confirm').value) return { error: 'Les deux mots de passe ne correspondent pas.' };
  }
  return { secret: { kind: 'password', value: password } };
}

function onJobEvent(event) {
  if (event.type === 'phase' && event.phase === 'kdf') {
    $('progress-label').textContent = 'Dérivation de la clé avec Argon2id…';
    $('progress').removeAttribute('value');
  } else if (event.type === 'progress') {
    const percent = event.total ? Math.round((event.done / event.total) * 100) : 100;
    $('progress-label').textContent = `${radioValue('action') === 'encrypt' ? 'Chiffrement' : 'Déchiffrement'}… ${percent} %`;
    $('progress').value = percent / 100;
  }
}

function showResult(blob, action) {
  const name = outputName(file.name, action);
  resultUrl = URL.createObjectURL(blob);
  $('download').href = resultUrl;
  $('download').download = name;
  $('download').textContent = `Télécharger ${name}`;
  $('result-title').textContent = action === 'encrypt' ? 'Fichier chiffré' : 'Fichier déchiffré et vérifié';

  const notes = [];
  if (action === 'encrypt') {
    notes.push(`${formatSize(blob.size)}. Vérifiez que vous avez conservé votre secret : sans lui, ce fichier est irrécupérable.`);
  } else {
    notes.push(`${formatSize(blob.size)}. Authentifié de bout en bout : le contenu n'a pas été modifié.`);
    if (resultTmpName) notes.push("Une copie temporaire reste dans le navigateur jusqu'à ce que vous cliquiez sur « Effacer ».");
  }
  $('result-note').textContent = notes.join(' ');
  showPanel('result');
}

async function start(event) {
  event.preventDefault();
  if (!file) return;
  showMessage(null);

  const action = radioValue('action');
  const { secret, error } = collectSecret(action);
  if (error) return showMessage(error);

  showPanel('progress');
  $('progress-label').textContent = 'Préparation…';
  $('progress').removeAttribute('value');

  try {
    await discardResult();
    await holdTmpLock();
    const { blob, tmpName } = await runWorker({ op: action, file, secret }, onJobEvent);
    resultTmpName = tmpName ?? null;
    $('password').value = '';
    $('confirm').value = '';
    showResult(blob, action);
  } catch (err) {
    showPanel('form');
    if (err.message !== 'cancelled') showMessage(ERRORS[err.message] ?? ERRORS.internal);
    await discardResult();
  }
}

async function generateKey() {
  try {
    const { key } = await runWorker({ op: 'generateKey' });
    $('key').value = key;
  } catch {
    showMessage(ERRORS.internal);
  }
}

async function copyKey() {
  if (!$('key').value) return;
  await navigator.clipboard.writeText($('key').value);
  $('copy-key').textContent = 'Copiée';
  setTimeout(() => { $('copy-key').textContent = 'Copier'; }, 1500);
}

function togglePasswordVisibility() {
  const reveal = $('password').type === 'password';
  $('password').type = reveal ? 'text' : 'password';
  $('confirm').type = reveal ? 'text' : 'password';
  $('toggle-password').textContent = reveal ? 'Masquer' : 'Afficher';
}

function bindDropzone() {
  // Sans ceci, lâcher un fichier à côté de la zone ferait naviguer vers lui.
  for (const type of ['dragover', 'drop']) {
    window.addEventListener(type, (event) => event.preventDefault());
  }
  const zone = $('dropzone');
  zone.addEventListener('dragover', () => zone.classList.add('active'));
  zone.addEventListener('dragleave', () => zone.classList.remove('active'));
  zone.addEventListener('drop', (event) => {
    zone.classList.remove('active');
    const { files } = event.dataTransfer;
    if (files.length > 1) return showMessage('Un seul fichier à la fois.');
    if (files.length === 1) selectFile(files[0]);
  });
}

function boot() {
  if (location.protocol === 'file:' || !window.isSecureContext || !navigator.locks) return;
  $('boot-error').hidden = true;
  $('form').hidden = false;

  bindDropzone();
  $('file').addEventListener('change', () => { if ($('file').files[0]) selectFile($('file').files[0]); });
  radios('action').concat(radios('method')).forEach((radio) => radio.addEventListener('change', () => {
    showMessage(null);
    render();
  }));
  $('form').addEventListener('submit', start);
  $('toggle-password').addEventListener('click', togglePasswordVisibility);
  $('generate-key').addEventListener('click', generateKey);
  $('copy-key').addEventListener('click', copyKey);
  $('reset').addEventListener('click', reset);
  $('cancel').addEventListener('click', () => {
    activeJob?.worker.terminate();
    activeJob?.reject(new Error('cancelled'));
    activeJob = null;
  });

  render();
  // Un onglet fermé avant « Effacer » peut avoir laissé un fichier temporaire.
  sweepTmpFiles().catch(() => {});
}

boot();
