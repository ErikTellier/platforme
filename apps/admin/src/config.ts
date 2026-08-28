import { optionsDeConfig, type OptionsDeConfig } from '@platforme/config';
import { z } from 'zod';

/**
 * LE SCHEMA DE CE SERVICE, ET DE LUI SEUL.
 *
 * `ADMIN_PORT` et non `PORT` : le .env est UNIQUE et vit a la racine. Une cle
 * non prefixee est prise par le premier service qui la lit, et le second n'a
 * plus aucun moyen d'en demander une autre.
 */
const schema = z.object({
  ADMIN_PORT: z.coerce.number().int().min(1).max(65535).default(3000),
});

/** Le type que `ConfigService` rendra, deduit du schema. */
export type ConfigAdmin = z.infer<typeof schema>;

/**
 * UNE FONCTION, ET NON UNE CONSTANTE.
 *
 * Une constante de module ferait ce travail a l'IMPORT, avant qu'aucun test
 * n'ait la main. Deux consequences, dans cet ordre d'importance :
 *
 *   1. Importer ce fichier declencherait une lecture du disque, meme pour un
 *      test qui ne veut que le type.
 *   2. Aucun test ne pourrait observer un changement de ces arguments — les
 *      tests de mutation l'ont montre : remplacer `{ dirname, schema }` par
 *      `{}` survivait, faute de pouvoir reevaluer le module.
 *
 * Un mutant qui survit signale toujours quelque chose. Ici, ce n'etait pas le
 * test qui manquait : c'etait la forme du code qui l'empechait.
 */
export function configAdmin(): OptionsDeConfig<ConfigAdmin> {
  return optionsDeConfig({ dirname: import.meta.dirname, schema });
}
