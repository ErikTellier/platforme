-- Up Migration

-- Un antislash ouvre une autorité, comme une barre oblique.
--
-- ═══ COMMENT CE TROU A ÉTÉ TROUVÉ ═══
--
-- Par CodeQL, et par lui seul. `gosec` et `semgrep` cherchent des formes ;
-- CodeQL suit le FLUX, et il a relié la valeur lue par `localPath` à l'en-tête
-- `Location` posé au retour d'authentification. Son verdict était précis :
-- « vérifie la barre oblique de tête, mais pas que le deuxième caractère ne
-- soit ni « / » ni « \ » ».
--
-- ═══ CE QUE ÇA PERMETTAIT ═══
--
-- `flow_redirect_is_local` refusait `//ailleurs.example` — une autorité déguisée
-- en dossier. Elle acceptait `/\ailleurs.example`.
--
-- Or les navigateurs NORMALISENT L'ANTISLASH EN BARRE OBLIQUE avant de résoudre
-- une adresse : la RFC 3986 ne le prévoit pas, le standard WHATWG des URL le
-- prescrit, et Chrome comme Firefox le font. `/\ailleurs.example` part donc
-- exactement où `//ailleurs.example` serait parti, en passant la garde.
--
-- « Une redirection après authentification est la forme la plus commode de
-- redirection ouverte » : c'est écrit à côté du test qui garde cette contrainte,
-- et la phrase valait déjà pour la forme qui manquait.
--
-- ═══ CE QUE ÇA NE PERMETTAIT PAS, AUJOURD'HUI ═══
--
-- La cible n'est pas lue dans la requête : `OpenLoginFlow` écrit `a.landing()`,
-- qui vient de la configuration. Il fallait donc un `.env` fautif pour y arriver.
--
-- Ce n'est pas une raison de la laisser. Toute la doctrine de cette base est que
-- L'INVARIANT VIT DANS LE DDL, précisément pour que le jour où un appelant
-- passera la cible du dehors — c'est la raison d'être du paramètre — la base
-- refuse ce que le service aura oublié de vérifier. Elle ne l'aurait pas refusé.
--
-- ═══ POURQUOI chr(92) ET NON UN ANTISLASH ÉCRIT ═══
--
-- Parce que `LIKE` traite l'antislash comme SON CARACTÈRE D'ÉCHAPPEMENT :
-- `LIKE '/\%'` ne cherche pas « / puis antislash », il cherche « / puis un
-- pour cent littéral ». La garde se serait relue comme une protection sans en
-- être une — le pire genre de défaut, et ce dépôt en a déjà rencontré un.
-- `left(…, 2) <> '/' || chr(92)` ne se prête à aucune lecture double, et `chr`
-- est immutable, ce qu'une contrainte exige.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. 23514 sur `flow_redirect_is_local`, comme avant —
--   c'est le NOM de la contrainte que le test assert, pas le code.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

ALTER TABLE admin.login_flow
  DROP CONSTRAINT flow_redirect_is_local;

ALTER TABLE admin.login_flow
  ADD CONSTRAINT flow_redirect_is_local
    CHECK (redirect_to IS NULL
           OR (left(redirect_to, 1) = '/'
               AND left(redirect_to, 2) <> '//'
               AND left(redirect_to, 2) <> '/' || chr(92)));

RESET ROLE;

-- Down Migration

SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

ALTER TABLE admin.login_flow
  DROP CONSTRAINT flow_redirect_is_local;

ALTER TABLE admin.login_flow
  ADD CONSTRAINT flow_redirect_is_local
    CHECK (redirect_to IS NULL
           OR (redirect_to LIKE '/%' AND redirect_to NOT LIKE '//%'));

RESET ROLE;
