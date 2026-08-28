import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { config } from './config.js';

/**
 * Ce que ce fichier verifie vraiment.
 *
 * Pas « zod fonctionne » — ce n'est pas notre code. Mais que LE SCHEMA DE CE
 * SERVICE dit ce qu'on croit : le defaut, les bornes, et un refus qui nomme la
 * cause. Une erreur ici ne se voit qu'au demarrage, en production.
 */
describe('config admin', () => {
  it('lit le .env de la racine du depot', () => {
    // Depuis apps/admin/src, la racine est trois niveaux au-dessus.
    const racine = resolve(import.meta.dirname, '..', '..', '..');

    expect(config.envFilePath).toBe(resolve(racine, '.env'));
  });

  it('retient 3000 quand ADMIN_PORT est absent', () => {
    expect(config.validate({})).toEqual({ ADMIN_PORT: 3000 });
  });

  it('convertit la chaine de l environnement en nombre', () => {
    // Une variable d'environnement est TOUJOURS une chaine : sans la coercion,
    // `app.listen` recevrait "8080" au lieu de 8080.
    expect(config.validate({ ADMIN_PORT: '8080' })).toEqual({
      ADMIN_PORT: 8080,
    });
  });

  it.each([
    ['zero, hors borne basse', '0'],
    ['au-dela du dernier port', '65536'],
    ['non entier', '3000.5'],
    ['non numerique', 'quatre-vingts'],
  ])('refuse un port %s', (_cas, valeur) => {
    expect(() => config.validate({ ADMIN_PORT: valeur })).toThrow(/ADMIN_PORT/);
  });

  it('accepte les bornes exactes', () => {
    expect(config.validate({ ADMIN_PORT: '1' })).toEqual({ ADMIN_PORT: 1 });
    expect(config.validate({ ADMIN_PORT: '65535' })).toEqual({
      ADMIN_PORT: 65535,
    });
  });

  it('ignore les variables etrangeres au schema', () => {
    // Le .env est PARTAGE : le schema d'admin doit laisser passer les cles des
    // autres services sans s'en emouvoir, et sans les recopier dans sa config.
    expect(
      config.validate({ ADMIN_PORT: '3000', AUTRE_SERVICE_PORT: '4000' }),
    ).toEqual({
      ADMIN_PORT: 3000,
    });
  });
});
