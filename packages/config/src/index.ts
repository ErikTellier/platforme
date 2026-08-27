import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import type { z, ZodType } from 'zod';

/**
 * Ce qui designe la racine du depot. On REMONTE jusqu'a lui plutot que de
 * compter des `..` : `resolve(dirname, '../../..')` encode la profondeur
 * `apps/<app>/dist`, et se trompe en silence le jour ou un paquet vit ailleurs.
 */
const MARQUEUR_DE_RACINE = 'pnpm-workspace.yaml';

/** Remonte depuis `depuis` jusqu'au dossier qui porte le marqueur de racine. */
export function racineDuDepot(depuis: string): string {
  let courant = resolve(depuis);

  for (;;) {
    if (existsSync(resolve(courant, MARQUEUR_DE_RACINE))) {
      return courant;
    }

    const parent = dirname(courant);
    if (parent === courant) {
      throw new Error(
        `Racine du depot introuvable depuis ${depuis} : aucun ${MARQUEUR_DE_RACINE} en remontant.`,
      );
    }
    courant = parent;
  }
}

/** Ce que `ConfigModule.forRoot` attend — decrit ici pour ne pas dependre de Nest. */
export interface OptionsDeConfig<T> {
  isGlobal: true;
  cache: true;
  envFilePath: string;
  validate: (brut: Record<string, unknown>) => T;
}

/**
 * Fabrique les options de `ConfigModule.forRoot` pour un service.
 *
 * ═══ POURQUOI CE PAQUET NE DEPEND PAS DE NEST ═══
 *
 * Le type rendu est decrit ici plutot qu'importe de `@nestjs/config` : la
 * compatibilite est STRUCTURELLE, donc un service qui n'est pas en Nest peut
 * appeler `validate` seul, et ce paquet n'impose Nest a personne.
 *
 * ═══ POURQUOI LE SCHEMA VIENT DE L'APPELANT ═══
 *
 * Chaque service n'a pas les memes variables. Un schema commun serait soit trop
 * laxiste — il laisserait demarrer un service auquel il manque sa propre cle —
 * soit trop large : chacun devrait declarer les variables des autres. Ce paquet
 * fournit donc la MECANIQUE, jamais le contenu.
 *
 * ═══ POURQUOI CA LEVE ═══
 *
 * Une variable absente sans validation donne un `undefined` qui se promene et
 * casse trois couches plus loin, dans un message qui ne nomme jamais la cause.
 * Ici le demarrage s'arrete, et l'erreur nomme la cle.
 *
 * @param options.dirname `import.meta.dirname` de l'appelant. Stable quel que
 *   soit le repertoire courant, contrairement a `process.cwd()`.
 * @param options.schema Le schema zod du service.
 */
export function optionsDeConfig<S extends ZodType>(options: {
  dirname: string;
  schema: S;
}): OptionsDeConfig<z.infer<S>> {
  const racine = racineDuDepot(options.dirname);
  const fichier = resolve(racine, '.env');

  return {
    isGlobal: true,
    cache: true,

    // UN SEUL .env, A LA RACINE. Un fichier absent n'est pas une faute : en
    // production les variables viennent de l'orchestrateur. C'est la validation
    // qui tranche, jamais la presence du fichier.
    envFilePath: fichier,

    validate: (brut) => {
      const resultat = options.schema.safeParse(brut);

      if (!resultat.success) {
        const details = resultat.error.issues
          .map((probleme) => {
            const cle = probleme.path.map(String).join('.');
            return `  ${cle === '' ? '(racine)' : cle} : ${probleme.message}`;
          })
          .join('\n');

        throw new Error(
          `Configuration invalide — le service ne demarre pas.\n${details}\n\n` +
            `Attendu dans : ${fichier}\n` +
            `Modele       : ${resolve(racine, '.env.example')}`,
        );
      }

      return resultat.data;
    },
  };
}
