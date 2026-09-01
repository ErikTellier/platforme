// @ts-check

// LES DOLLARS ORPHELINS.
//
// ═══ POURQUOI CE GARDE EXISTE ═══
//
// Dans une chaine de remplacement JavaScript, `$$` signifie « un `$` litteral ».
// Un `contenu.replace(motif, remplacement)` dont le remplacement contient du
// dollar-quoting transforme donc silencieusement `$$DELETE FROM t$$` en
// `$DELETE FROM t$`.
//
// C'est arrive CINQ fois dans une seule session, dont une qui a gache une
// campagne de mutation entiere. Le defaut ne se voit pas a la lecture : il
// remonte plus loin, sous forme d'erreur de syntaxe a un endroit sans rapport,
// parce que le corps dollar-quote ne se ferme plus, ou se ferme trop loin.
//
// ═══ POURQUOI COMPTER LES `$$` NE SUFFIT PAS ═══
//
// Une premiere version comptait les `$$` et exigeait un nombre pair. Deux paires
// cassees symetriquement laissent le compte pair : mesure faite, un banc casse
// passait de quatorze paires a quatorze. Le garde restait vert sur un fichier
// mort. Il faut donc reconnaitre les usages LEGITIMES du dollar et signaler tout
// le reste.
//
// ═══ ET POURQUOI IL FAUT LEXER, PAS GREPPER ═══
//
// La premiere version de CE fichier signalait neuf faux positifs, tous de la
// meme forme :
//
//     CHECK (code ~ '^[A-Z][A-Z_]{2,31}$')
//
// Un `$` d'ancrage de fin dans une expression reguliere. Le dollar n'a de sens
// syntaxique qu'en dehors des litteraux et des commentaires ; les traverser sans
// les reconnaitre rend le garde bruyant, et un garde bruyant finit desactive.

import { readFileSync, globSync } from 'node:fs';
import { text } from 'node:stream/consumers';
import process from 'node:process';

/** Un delimiteur dollar, anonyme (`$$`) ou nomme (`$corps$`). */
const DELIMITEUR = /^\$([A-Za-z_]\w*)?\$/;
/** Un parametre positionnel : `$1`, `$2`. */
const POSITIONNEL = /^\$\d+/;

/**
 * Chaque lecteur rend l'index qui SUIT le fragment reconnu, ou -1 si le texte ne
 * commence pas par le fragment qu'il sait lire. Les separer ainsi garde chacun
 * lisible — la version monolithique atteignait une complexite de 17.
 *
 * @typedef {(texte: string, i: number) => number} Lecteur
 */

/**
 * La forme du JSON que le crochet envoie. Declaree parce qu'elle vient de
 * l'exterieur : rien ne garantit qu'elle soit celle-la, d'ou les `?`.
 *
 * @typedef {{
 *   tool_input?: { file_path?: unknown },
 *   tool_response?: { filePath?: unknown },
 * }} Appel
 */

/** Un commentaire de ligne : le dollar y est de la prose. @type {Lecteur} */
function commentaireDeLigne(texte, i) {
  if (texte[i] !== '-' || texte[i + 1] !== '-') return -1;
  const fin = texte.indexOf('\n', i);
  return fin === -1 ? texte.length : fin;
}

/** Un commentaire de bloc, non imbrique — suffisant ici. @type {Lecteur} */
function commentaireDeBloc(texte, i) {
  if (texte[i] !== '/' || texte[i + 1] !== '*') return -1;
  const fin = texte.indexOf('*/', i + 2);
  return fin === -1 ? texte.length : fin + 2;
}

/**
 * Un litteral. Le dollar y est une donnee, le plus souvent une ancre de regex.
 * `''` est l'echappement standard : il ne ferme pas le litteral.
 *
 * @type {Lecteur}
 */
function litteral(texte, i) {
  if (texte[i] !== "'") return -1;
  let j = i + 1;
  while (j < texte.length) {
    if (texte[j] !== "'") j += 1;
    else if (texte[j + 1] === "'") j += 2;
    else return j + 1;
  }
  return texte.length;
}

/** Un dollar a sa place : delimiteur ou parametre. @type {Lecteur} */
function dollarLegitime(texte, i) {
  if (texte[i] !== '$') return -1;
  const reste = texte.slice(i);
  const trouve = DELIMITEUR.exec(reste) ?? POSITIONNEL.exec(reste);
  return trouve ? i + trouve[0].length : -1;
}

/** @type {Lecteur[]} */
const LECTEURS = [
  commentaireDeLigne,
  commentaireDeBloc,
  litteral,
  dollarLegitime,
];

/**
 * @param {string} texte
 * @param {number} index
 */
function situer(texte, index) {
  const avant = texte.slice(0, index);
  const debutDeLigne = avant.lastIndexOf('\n') + 1;
  const finDeLigne = texte.indexOf('\n', index);
  return {
    ligne: avant.split('\n').length,
    colonne: index - debutDeLigne + 1,
    extrait: texte
      .slice(debutDeLigne, finDeLigne === -1 ? texte.length : finDeLigne)
      .trim(),
  };
}

/**
 * @param {string} texte
 * @returns {{ ligne: number, colonne: number, extrait: string }[]}
 */
export function orphelins(texte) {
  const trouves = [];

  for (let i = 0; i < texte.length;) {
    let saut = -1;
    for (const lire of LECTEURS) {
      saut = lire(texte, i);
      if (saut !== -1) break;
    }
    if (saut !== -1) {
      i = saut;
      continue;
    }
    if (texte[i] === '$') trouves.push(situer(texte, i));
    i += 1;
  }

  return trouves;
}

/**
 * Le mode crochet : Claude Code envoie sur l'entree standard le JSON de l'appel
 * d'outil qui vient d'aboutir. On n'a pas `jq` sur cette machine — verifie, pas
 * suppose — donc c'est Node qui lit son propre JSON.
 *
 * @returns {Promise<string[]>}
 */
async function depuisLeCrochet() {
  try {
    /** @type {unknown} */
    const analyse = JSON.parse(await text(process.stdin));
    const appel = /** @type {Appel} */ (analyse);
    const chemin = appel.tool_input?.file_path ?? appel.tool_response?.filePath;
    return typeof chemin === 'string' ? [chemin] : [];
  } catch {
    return []; // Un JSON qu'on ne comprend pas n'est pas une faute du depot.
  }
}

const crochet = process.argv.includes('--crochet');
const nommes = process.argv.slice(2).filter((a) => a !== '--crochet');

/** @returns {Promise<string[]>} */
async function choisirLesCibles() {
  if (crochet) return depuisLeCrochet();
  if (nommes.length > 0) return nommes;
  return globSync(['tests/pgtap/**/*.sql', 'migrations/**/*.sql']);
}

const cibles = await choisirLesCibles();

let fautifs = 0;

for (const chemin of cibles) {
  if (!chemin.endsWith('.sql')) continue;

  /** @type {string} */
  let texte;
  try {
    texte = readFileSync(chemin, 'utf8');
  } catch {
    continue; // Un fichier supprime entre-temps n'est pas une faute.
  }

  for (const { ligne, colonne, extrait } of orphelins(texte)) {
    fautifs += 1;
    process.stderr.write(
      `${chemin}:${String(ligne)}:${String(colonne)}  dollar orphelin — un « $$ » mange ?\n` +
        `    ${extrait}\n`,
    );
  }
}

if (fautifs > 0) {
  process.stderr.write(
    `\n${String(fautifs)} dollar(s) orphelin(s). Un « $$ » de delimitation a ete\n` +
      `remplace par un « $ » simple — presque toujours un String.replace() en\n` +
      `JavaScript, ou « $$ » veut dire « un $ litteral ». Editer avec l'outil Edit.\n`,
  );
  process.exit(crochet ? 2 : 1);
}

if (!crochet && nommes.length === 0) {
  process.stdout.write(
    `${String(cibles.length)} fichier(s) SQL, aucun dollar orphelin\n`,
  );
}
