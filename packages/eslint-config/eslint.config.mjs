// La configuration se lint AVEC ELLE-MEME. Toute regle durcie ici s'applique
// donc d'abord a son propre auteur.
import { base } from './base.js';

export default base({ tsconfigRootDir: import.meta.dirname });
