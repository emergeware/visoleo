#!/usr/bin/env node
/**
 * build.mjs — gera o vault cifrado e o portal publicável.
 *
 * O conteúdo em claro e a passphrase vivem FORA deste repositório, em
 * ../visoleo-source/. Isso é deliberado: tudo o que está dentro da pasta do
 * repo acaba publicado mais cedo ou mais tarde, mesmo listado no .gitignore.
 * Manter o segredo fora torna o vazamento estruturalmente impossível em vez de
 * o fazer depender de disciplina.
 *
 * Esquema:
 *
 *   passphrase --Argon2id(64 MiB, t=4, p=1, salt 16B)--> chave mestra (256 bits)
 *   chave mestra --HKDF-SHA256(info por documento)-----> chave do documento
 *   HTML --gzip--> AES-256-GCM(aad = nome do ficheiro) --> IV | ciphertext | tag
 *
 * A tag GCM é o verificador da senha. Não existe hash de senha publicado, logo
 * um atacante não tem nenhum valor derivado para atacar antes de pagar o custo
 * do Argon2id em cada tentativa.
 *
 * O repositório é público: o ciphertext é descarregável por qualquer pessoa e o
 * ataque é offline, sem limite de tentativas. A única defesa real é o custo por
 * tentativa vezes a entropia da passphrase. Por isso o Argon2id não é enfeite e
 * a verificação de entropia aborta o build.
 */

import { argon2id } from 'hash-wasm';
import {
  createCipheriv, createDecipheriv, randomBytes, hkdfSync, createHash,
} from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import {
  readFileSync, writeFileSync, rmSync, mkdirSync, readdirSync, statSync, existsSync,
} from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = dirname(fileURLToPath(import.meta.url));
const SOURCE = join(REPO, '..', 'visoleo-source');
const VAULT = join(REPO, 'vault');

/** Parâmetros do Argon2id. 64 MiB é escolha conservadora: um dos documentos é
 *  para telemóvel, e alocações muito maiores falham em aparelhos antigos. */
const KDF = { alg: 'argon2id', m: 65536, t: 4, p: 1, len: 32 };

/** Entropia mínima aceite para a passphrase, em bits. Abaixo disto o Argon2id
 *  atrasa o ataque mas não o impede. */
const MIN_ENTROPY_BITS = 60;

/** Ficheiros que descrevem o conteúdo e por isso vivem do lado do conteúdo,
 *  fora deste repositório. Este script é público: nomear aqui os documentos ou
 *  os seus rótulos entregaria de graça parte do que a senha protege. */
const SOURCE_FILES = {
  env: '.env',
  markers: 'leak-markers.json',
  docs: 'docs.json',
  wordlist: '.wordlist.txt',
};

const die = (msg) => { console.error(`\n  ERRO: ${msg}\n`); process.exit(1); };
const say = (msg) => console.log(msg);

// --- Pré-condições -------------------------------------------------------

// Um segredo dentro do repo anula toda a criptografia. Aborta antes de gerar o
// que quer que seja.
for (const leak of Object.values(SOURCE_FILES)) {
  if (existsSync(join(REPO, leak))) {
    die(`'${leak}' está dentro do repositório e seria publicado.\n`
      + `  Mova-o para ${SOURCE} e volte a correr.`);
  }
}
if (!existsSync(SOURCE)) die(`fonte não encontrada: ${SOURCE}`);

const envPath = join(SOURCE, SOURCE_FILES.env);
if (!existsSync(envPath)) {
  die(`passphrase não encontrada: ${envPath}\n`
    + '  Crie o ficheiro com a linha: VISOLEO_PASSPHRASE=<passphrase>');
}
const passphrase = (readFileSync(envPath, 'utf8').match(/^VISOLEO_PASSPHRASE=(.*)$/m) || [])[1]?.trim();
if (!passphrase) die(`${envPath} não contém a linha VISOLEO_PASSPHRASE=<passphrase>`);

const markerPath = join(SOURCE, SOURCE_FILES.markers);
if (!existsSync(markerPath)) {
  die(`lista de termos não encontrada: ${markerPath}\n`
    + '  Sem ela as verificações de vazamento não correm, e o build não se pode declarar seguro.');
}
const MARKERS = JSON.parse(readFileSync(markerPath, 'utf8')).forbidden;
if (!Array.isArray(MARKERS) || MARKERS.length === 0) {
  die(`${markerPath} não tem a chave 'forbidden' com termos.`);
}

const docsPath = join(SOURCE, SOURCE_FILES.docs);
if (!existsSync(docsPath)) die(`lista de documentos não encontrada: ${docsPath}`);
const DOCS = JSON.parse(readFileSync(docsPath, 'utf8')).docs;
if (!Array.isArray(DOCS) || DOCS.length === 0) {
  die(`${docsPath} não tem a chave 'docs' com documentos.`);
}
for (const d of DOCS) {
  for (const field of ['id', 'file', 'label', 'note']) {
    if (!d[field]) die(`documento sem '${field}' em ${docsPath}: ${JSON.stringify(d)}`);
  }
  if (!existsSync(join(SOURCE, d.file))) die(`documento não encontrado: ${join(SOURCE, d.file)}`);
}

// --- Entropia da passphrase ----------------------------------------------

/**
 * Estima a entropia da passphrase. Se ela for uma sequência de palavras da
 * lista EFF, a conta correta é nPalavras * log2(tamanhoDaLista) — a estimativa
 * por conjunto de caracteres SOBREestima aqui, e sobrestimar entropia num
 * portão de segurança é pior do que não verificar nada.
 */
function estimateEntropy(pass) {
  const wordlistPath = join(SOURCE, SOURCE_FILES.wordlist);
  const tokens = pass.split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  if (existsSync(wordlistPath) && tokens.length >= 3) {
    const words = new Set(
      readFileSync(wordlistPath, 'utf8').trim().split(/\r?\n/)
        .map((l) => l.split('\t').pop().trim().toLowerCase()),
    );
    if (tokens.every((t) => words.has(t.toLowerCase()))) {
      return {
        bits: tokens.length * Math.log2(words.size),
        how: `${tokens.length} palavras de uma lista de ${words.size}`,
      };
    }
  }
  let space = 0;
  if (/[a-z]/.test(pass)) space += 26;
  if (/[A-Z]/.test(pass)) space += 26;
  if (/[0-9]/.test(pass)) space += 10;
  if (/[^a-zA-Z0-9]/.test(pass)) space += 33;
  return {
    bits: pass.length * Math.log2(space || 1),
    how: `${pass.length} caracteres, assumindo escolha aleatória`,
  };
}

const entropy = estimateEntropy(passphrase);
if (entropy.bits < MIN_ENTROPY_BITS) {
  die(`passphrase fraca demais: ~${entropy.bits.toFixed(0)} bits (${entropy.how}).\n`
    + `  Mínimo ${MIN_ENTROPY_BITS} bits. O ciphertext é público e o ataque é offline;\n`
    + '  o Argon2id atrasa cada tentativa mas não substitui entropia.');
}

// --- Primitivas ----------------------------------------------------------

/** Nome do ficheiro derivado do salt: não revela o documento a quem só tem a
 *  URL do site. Determinístico dentro do mesmo build. */
const blobName = (salt, id) => `${createHash('sha256').update(salt).update(`name/${id}`).digest('hex').slice(0, 16)}.bin`;

/** HKDF-SHA256. A mesma derivação corre no browser via WebCrypto. */
const subKey = (master, salt, info) => Buffer.from(hkdfSync('sha256', master, salt, Buffer.from(info, 'utf8'), 32));

/** AES-256-GCM. O nome do ficheiro entra como AAD: liga o ciphertext ao seu
 *  lugar, de modo que trocar dois blobs entre si é detectado. */
function seal(key, aad, plaintext) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]);
}

function unseal(key, aad, blob) {
  const d = createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
  d.setAAD(Buffer.from(aad, 'utf8'));
  d.setAuthTag(blob.subarray(blob.length - 16));
  return Buffer.concat([d.update(blob.subarray(12, blob.length - 16)), d.final()]);
}

// --- Cifragem ------------------------------------------------------------

say('');
say(`  fonte      : ${SOURCE}`);
say(`  destino    : ${REPO}`);
say(`  passphrase : ~${entropy.bits.toFixed(0)} bits (${entropy.how})`);
say('');
say(`  a derivar a chave mestra com Argon2id (${KDF.m / 1024} MiB, t=${KDF.t})...`);

const salt = randomBytes(16);
const t0 = process.hrtime.bigint();
const master = Buffer.from(await argon2id({
  password: passphrase,
  salt,
  memorySize: KDF.m,
  iterations: KDF.t,
  parallelism: KDF.p,
  hashLength: KDF.len,
  outputType: 'binary',
}));
say(`  chave mestra derivada em ${(Number(process.hrtime.bigint() - t0) / 1e6).toFixed(0)} ms`);
say('');

rmSync(VAULT, { recursive: true, force: true });
mkdirSync(VAULT, { recursive: true });

const sources = new Map(DOCS.map((d) => [d.id, readFileSync(join(SOURCE, d.file))]));

const catalog = [];
let plainTotal = 0;
let encTotal = 0;

for (const doc of DOCS) {
  const plain = sources.get(doc.id);
  const name = blobName(salt, doc.id);
  const key = subKey(master, salt, `visoleo/v1/doc/${doc.id}`);
  const blob = seal(key, name, gzipSync(plain, { level: 9 }));
  writeFileSync(join(VAULT, name), blob);

  catalog.push({
    id: doc.id, label: doc.label, note: doc.note, file: name,
  });
  plainTotal += plain.length;
  encTotal += blob.length;
  say(`  ${doc.id.padEnd(11)} ${String(plain.length).padStart(8)} B  ->  ${String(blob.length).padStart(7)} B   ${name}`);
}

// O catálogo também é cifrado: os rótulos dizem o que há atrás da senha.
const catName = blobName(salt, '__catalog__');
const catKey = subKey(master, salt, 'visoleo/v1/catalog');
const catPlain = Buffer.from(JSON.stringify(catalog), 'utf8');
writeFileSync(join(VAULT, catName), seal(catKey, catName, gzipSync(catPlain, { level: 9 })));

writeFileSync(join(VAULT, 'manifest.json'), `${JSON.stringify({
  v: 1,
  cipher: 'AES-256-GCM',
  kdf: { ...KDF, salt: salt.toString('base64') },
  catalog: catName,
}, null, 2)}\n`);

// --- Portal --------------------------------------------------------------

const template = join(REPO, 'src', 'portal.html');
if (!existsSync(template)) die(`template do portal não encontrado: ${template}`);

// O bundle do Argon2id vai embutido em base64: assim o portal é um ficheiro
// único, sem CDN nem pedido externo antes da senha, e nenhuma sequência dentro
// do bundle minificado consegue partir o HTML que a envolve.
const argonUmd = readFileSync(join(REPO, 'node_modules', 'hash-wasm', 'dist', 'argon2.umd.min.js'));
const portal = readFileSync(template, 'utf8');
if (!portal.includes('__ARGON2_B64__')) die('o template do portal não tem o marcador __ARGON2_B64__.');
const html = portal.replace('__ARGON2_B64__', () => argonUmd.toString('base64'));

// Uma marca de fecho de script dentro do código inline — mesmo dentro de um
// comentário, que o parser de HTML não distingue de código — corta o script a
// meio, e o resto do ficheiro passa a ser lido como marcação. A falha é
// silenciosa: nenhum erro na consola, os listeners simplesmente nunca se ligam.
// Por isso é o build que a apanha, e não quem for abrir a página.
const scriptStart = html.indexOf('<script>');
const scriptEnd = html.lastIndexOf('</script>');
if (scriptStart < 0 || scriptEnd < scriptStart) die('o portal gerado não tem um bloco <script> reconhecível.');
if (/<\/script/i.test(html.slice(scriptStart + '<script>'.length, scriptEnd))) {
  die('o código inline do portal contém uma marca de fecho de script.\n'
    + '  O parser de HTML cortaria o script aí, sem dar erro nenhum.');
}

writeFileSync(join(REPO, 'index.html'), html);

// --- Verificação: ida e volta --------------------------------------------

// Cifrar é fácil; cifrar e conseguir voltar atrás é o que interessa. Sem esta
// verificação o build pode publicar lixo com ar de cifrado.
for (const entry of catalog) {
  const blob = readFileSync(join(VAULT, entry.file));
  const key = subKey(master, salt, `visoleo/v1/doc/${entry.id}`);
  let back;
  try {
    back = gunzipSync(unseal(key, entry.file, blob));
  } catch (e) {
    die(`ida e volta falhou em '${entry.id}': ${e.message}`);
  }
  if (!back.equals(sources.get(entry.id))) {
    die(`ida e volta em '${entry.id}' devolveu bytes diferentes do original.`);
  }
}
try {
  const back = gunzipSync(unseal(catKey, catName, readFileSync(join(VAULT, catName))));
  if (!back.equals(catPlain)) die('ida e volta do catálogo devolveu bytes diferentes.');
} catch (e) {
  die(`ida e volta do catálogo falhou: ${e.message}`);
}

// Uma senha errada tem de falhar na autenticação, não devolver lixo.
try {
  unseal(
    subKey(Buffer.alloc(32, 7), salt, `visoleo/v1/doc/${catalog[0].id}`),
    catalog[0].file,
    readFileSync(join(VAULT, catalog[0].file)),
  );
  die('uma chave errada conseguiu decifrar um documento. O esquema está partido.');
} catch (e) {
  if (!/auth/i.test(e.message)) die(`chave errada falhou pelo motivo errado: ${e.message}`);
}

// --- Verificação: nenhum termo em claro no repositório -------------------

// Um marcador que não corresponde a nada dá uma sensação falsa de segurança.
const haystack = [...sources.values()].map((b) => b.toString('utf8').toLowerCase());
const missing = MARKERS.filter((m) => !haystack.some((h) => h.includes(m.toLowerCase())));
if (missing.length) {
  die(`estes termos de leak-markers.json não existem em nenhum documento fonte: ${missing.join(', ')}.\n`
    + '  Um marcador que não corresponde a nada dá uma sensação falsa de segurança.');
}

// Cifrar o conteúdo não protege nada se o mesmo texto estiver legível num
// ficheiro ao lado. Por isso a varredura é ao repositório inteiro, não só ao
// que este build acabou de gerar.
const SKIP = new Set(['.git', 'node_modules']);
const walk = (dir) => readdirSync(dir).flatMap((n) => {
  if (SKIP.has(n)) return [];
  const p = join(dir, n);
  return statSync(p).isDirectory() ? walk(p) : [p];
});

const published = walk(REPO);
const leaked = [];
for (const p of published) {
  const text = readFileSync(p).toString('utf8').toLowerCase();
  for (const m of MARKERS) {
    if (text.includes(m.toLowerCase())) leaked.push(`${relative(REPO, p)}: '${m}'`);
  }
}
if (leaked.length) {
  rmSync(VAULT, { recursive: true, force: true });
  die('VAZAMENTO — termos do conteúdo aparecem em claro em ficheiros publicados.\n'
    + '  A senha não protege nada enquanto isto existir. Vault descartado.\n\n'
    + `  ${leaked.join('\n  ')}`);
}

// --- Relatório -----------------------------------------------------------

say('');
say('  OK — vault cifrado gerado.');
say(`       ${plainTotal.toLocaleString('pt-PT')} B em claro  ->  ${encTotal.toLocaleString('pt-PT')} B cifrados  (${(100 - (encTotal / plainTotal) * 100).toFixed(0)}% menor)`);
say(`       ida e volta verificada nos ${catalog.length} documentos e no catálogo`);
say('       chave errada rejeitada pela tag GCM');
say(`       ${MARKERS.length} termos verificados, nenhum em claro em ${published.length} ficheiros`);
say('');
say('  Publique commitando index.html e vault/. Não copie nada de visoleo-source para cá.');
say('');
