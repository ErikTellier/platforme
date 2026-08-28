import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { optionsDeConfig, racineDuDepot } from './index.js';

/** Racines temporaires creees par un test, effacees apres lui. */
const aNettoyer: string[] = [];

afterEach(() => {
  while (aNettoyer.length > 0) {
    const chemin = aNettoyer.pop();
    if (chemin !== undefined) rmSync(chemin, { recursive: true, force: true });
  }
});

/** Fabrique un faux depot : une racine porteuse du marqueur, et un sous-arbre. */
function fauxDepot(sousChemin: string): { racine: string; profond: string } {
  const racine = mkdtempSync(join(tmpdir(), 'platforme-'));
  aNettoyer.push(racine);

  writeFileSync(join(racine, 'pnpm-workspace.yaml'), 'packages: []\n');

  const profond = join(racine, sousChemin);
  mkdirSync(profond, { recursive: true });

  return { racine, profond };
}

describe('racineDuDepot', () => {
  it('remonte jusqu au dossier portant pnpm-workspace.yaml', () => {
    const { racine, profond } = fauxDepot(join('apps', 'admin', 'dist'));

    // `resolve` des deux cotes : sous macOS, tmpdir() passe par /var, lien
    // symbolique vers /private/var, et la comparaison brute echouerait.
    expect(resolve(racineDuDepot(profond))).toBe(resolve(racine));
  });

  it('rend le dossier lui-meme quand il porte deja le marqueur', () => {
    const { racine } = fauxDepot('vide');

    expect(resolve(racineDuDepot(racine))).toBe(resolve(racine));
  });

  it('leve, en nommant le marqueur, quand aucune racine n existe', () => {
    // La racine du systeme de fichiers ne contient pas pnpm-workspace.yaml :
    // la remontee y bute sur `parent === courant`.
    const racineSysteme = resolve('/');

    expect(() => racineDuDepot(racineSysteme)).toThrow(/pnpm-workspace\.yaml/);
  });
});

describe('optionsDeConfig', () => {
  const schema = z.object({
    ADMIN_PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  });

  it('vise le .env de la racine, pas celui du dossier appelant', () => {
    const { racine, profond } = fauxDepot(join('apps', 'admin', 'dist'));

    const options = optionsDeConfig({ dirname: profond, schema });

    expect(options.envFilePath).toBe(resolve(racine, '.env'));
    expect(options.isGlobal).toBe(true);
    expect(options.cache).toBe(true);
  });

  it('rend les valeurs analysees quand l entree est valide', () => {
    const { profond } = fauxDepot('dist');

    const { validate } = optionsDeConfig({ dirname: profond, schema });

    expect(validate({ ADMIN_PORT: '8080' })).toEqual({ ADMIN_PORT: 8080 });
  });

  it('applique le defaut du schema quand la cle est absente', () => {
    const { profond } = fauxDepot('dist');

    const { validate } = optionsDeConfig({ dirname: profond, schema });

    expect(validate({})).toEqual({ ADMIN_PORT: 3000 });
  });

  it('leve en nommant la cle fautive et le fichier attendu', () => {
    const { racine, profond } = fauxDepot('dist');

    const { validate } = optionsDeConfig({ dirname: profond, schema });

    try {
      validate({ ADMIN_PORT: '99999' });
      expect.unreachable('la validation aurait du lever');
    } catch (erreur) {
      const message = (erreur as Error).message;

      // Le message doit permettre de corriger SANS lire le code : quelle cle,
      // quel probleme, et ou ecrire la valeur.
      expect(message).toContain('ADMIN_PORT');
      expect(message).toContain(resolve(racine, '.env'));
      expect(message).toContain(resolve(racine, '.env.example'));
    }
  });

  it('nomme (racine) quand le probleme ne porte sur aucune cle', () => {
    const { profond } = fauxDepot('dist');

    // Un schema qui rejette l objet entier : `path` est vide, et la branche
    // `cle === ''` du formatage doit alors afficher `(racine)`.
    const schemaRefusant = z.object({}).refine(() => false, 'entree refusee');

    const { validate } = optionsDeConfig({
      dirname: profond,
      schema: schemaRefusant,
    });

    expect(() => validate({})).toThrow(/\(racine\)/);
  });
});
