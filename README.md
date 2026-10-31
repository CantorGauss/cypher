# Cypher

Chiffrement de fichiers 100 % côté navigateur, dans l'esprit de [hat.sh](https://hat.sh).
Aucun serveur applicatif, aucune étape de build : sept fichiers statiques, soit 1,4 Mo.

```
public/
├── index.html
├── style.css
├── app.js                       interface
├── worker.js                    chiffrement, dans un Web Worker
└── vendor/
    ├── libsodium-sumo.js        libsodium 0.8.4 (WebAssembly embarqué)
    ├── libsodium-wrappers.js
    └── LICENSE
```

## Déployer

Copiez le contenu de `public/` sur n'importe quel hébergement statique : Nginx, GitHub Pages,
Cloudflare Pages, Netlify, S3… Il n'y a rien à compiler ni à configurer.

La page doit être servie en **HTTPS** (ou sur `localhost`). Les API du navigateur dont elle dépend
sont réservées aux contextes sécurisés, et elle ne fonctionne pas ouverte directement en `file://`.

Pour l'essayer en local :

```bash
python3 -m http.server --directory public 8000
```

puis ouvrez <http://localhost:8000>.

Si votre hébergeur permet de définir des en-têtes, ajoutez celui-ci (optionnel, mais recommandé).
Il couvre le Worker, que la balise `<meta>` de la page ne couvre pas, et interdit l'inclusion de la
page dans une iframe :

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src data:; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

## Cryptographie

| Rôle | Choix |
| --- | --- |
| Chiffrement authentifié | XChaCha20-Poly1305 en flux (`crypto_secretstream`), clé de 256 bits, nonce de 192 bits |
| Mot de passe vers clé | Argon2id, 256 Mio, 3 passes, sel aléatoire de 128 bits |
| Mode clé | Clé aléatoire de 256 bits générée par libsodium, encodée en base64url (43 caractères) |
| Aléa | `crypto.getRandomValues` du navigateur, via libsodium |

Propriétés utiles :

- **Rien ne sort du navigateur.** Le fichier est lu et traité localement, et le code n'ouvre aucune connexion.
  La CSP de la page interdit en plus toute connexion réseau, et l'en-tête ci-dessus étend cette interdiction au
  Worker.
- **Aucun clair avant vérification.** Le résultat d'un déchiffrement n'est proposé qu'une fois le dernier bloc
  authentifié. Un fichier altéré, tronqué, réordonné ou prolongé ne produit rien.
- **Gros fichiers.** Le traitement se fait par blocs de 1 Mio et la sortie passe par le stockage privé du
  navigateur (OPFS) : la taille n'est pas limitée par la RAM, mais il faut environ deux fois la taille du
  fichier en espace disque libre le temps de l'opération. Si l'OPFS est indisponible (certains modes de
  navigation privée), le résultat reste en mémoire et la limite est de 2 Gio.
- **Mémoire.** Chaque opération a son propre Worker, détruit à la fin.

## Ce que cet outil ne garantit pas

- **Il n'a pas été audité.** libsodium est une référence éprouvée, mais le code de ce dépôt et son format de
  fichier n'ont reçu aucun audit indépendant. Ne supprimez pas un original avant d'avoir vérifié que vous savez
  le déchiffrer.
- **Un mot de passe ne vaut pas une clé de 256 bits.** La clé dérivée fait 256 bits, mais sa résistance réelle
  se limite à celle du mot de passe. Argon2id ralentit les attaques sans compenser un mot de passe faible.
  Pour une sécurité de 256 bits effectifs, utilisez le mode clé.
- **Vous faites confiance à l'hébergeur à chaque visite.** Comme pour tout outil web, le serveur peut livrer un
  autre code. Hébergez-le vous-même, ou lancez-le en local, si ce risque compte pour vous.
- **Le navigateur et la machine sont supposés sains.** Une extension ou un logiciel malveillant peut lire le
  mot de passe ou le fichier.
- **La mémoire n'est pas effacée de façon garantie.** Les clés sont remises à zéro dans WebAssembly, mais les
  chaînes JavaScript (mot de passe, clé collée) ne peuvent pas l'être.
- **« Effacer » n'est pas un effacement sécurisé.** Le fichier temporaire de l'OPFS est supprimé, sans
  écrasement physique des secteurs. Si l'onglet est fermé avant, il est supprimé à la prochaine visite.
- **Le nom et la taille ne sont pas masqués.** Le nom d'origine reste visible dans `nom.ext.cypher`, et la taille
  du fichier chiffré révèle celle du clair.
- **Pas de partage asymétrique.** Il n'y a pas de clé publique : le secret doit être transmis par un canal sûr.

## Format de fichier (v1)

Les entiers sont en little-endian. L'en-tête fait 56 octets :

| Offset | Taille | Contenu |
| --- | --- | --- |
| 0 | 4 | `CYPH` |
| 4 | 1 | Version, `1` |
| 5 | 1 | Mode : `1` mot de passe, `2` clé |
| 6 | 2 | Réservé, `0` |
| 8 | 4 | Argon2id : passes (`0` en mode clé) |
| 12 | 4 | Argon2id : mémoire en Kio (`0` en mode clé) |
| 16 | 16 | Sel Argon2id (zéros en mode clé) |
| 32 | 24 | En-tête `crypto_secretstream_xchacha20poly1305` |

Puis viennent les blocs `crypto_secretstream` : 1 Mio de clair pour chacun, sauf le dernier, soit 17 octets de
plus une fois chiffré. Le dernier porte `TAG_FINAL` et tous les autres `TAG_MESSAGE`. Un fichier vide produit un
unique bloc final vide. Les 56 octets d'en-tête servent de données additionnelles authentifiées à chaque bloc.

En mode mot de passe, la clé vaut
`crypto_pwhash(32, NFC(mot de passe) en UTF-8, sel, passes, mémoire × 1024, ALG_ARGON2ID13)`.
En mode clé, les 32 octets sont utilisés directement.

Cette description suffit pour relire un fichier sans le site : `tests/e2e.mjs` contient un décodeur Node
indépendant, écrit à partir de cette spécification.

## Mettre à jour libsodium

Remplacez les deux fichiers de `public/vendor/` par ceux des paquets npm `libsodium-sumo` et
`libsodium-wrappers-sumo` (`dist/modules-sumo/`), puis relancez les tests.

Empreintes SHA-256 de la version 0.8.4 livrée ici :

```
a3d0b7eb2c24ba6b5401d88717e65bc6a92786d211bc8b91ed746d24226180f3  libsodium-sumo.js
4e2c5442899321d7d9aea69bef71a3c24a6eab5911b74a5c1ad8bc8c733b0a15  libsodium-wrappers.js
```

## Tests

`package.json` ne sert qu'aux tests, le site n'en dépend pas.

```bash
npm install
```

```bash
npm test
```

Les tests pilotent l'interface dans de vrais navigateurs, Chrome et WebKit par défaut. Ils couvrent les
allers-retours aux tailles limites, l'interopérabilité avec le décodeur indépendant, les altérations, le nettoyage
des fichiers temporaires et les gros fichiers. WebKit demande `npx playwright install webkit`, et Firefox s'active
avec `BROWSERS=chrome,webkit,firefox` après `npx playwright install firefox`.
