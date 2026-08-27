import { optionsDeConfig } from '@platforme/config';
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

export const config = optionsDeConfig({ dirname: import.meta.dirname, schema });
