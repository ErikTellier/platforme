-- LA REDIRECTION APRÈS CONNEXION, ET CE QU'ELLE NE DOIT PAS OUVRIR.
--
-- ═══ L'INVARIANT QUE CE FICHIER DÉFEND ═══
--
-- Après authentification, le service renvoie l'administrateur là où il voulait
-- aller. Cette destination vient de l'URL de départ, donc de l'extérieur. Si
-- elle peut désigner un site tiers, on obtient une REDIRECTION OUVERTE : un
-- lien qui part du domaine légitime, passe par une vraie connexion, et dépose
-- la personne authentifiée sur une page qui l'attend.
--
-- C'est l'hameçonnage le plus convaincant qui soit, parce que tout y est vrai
-- sauf la dernière étape.
--
-- ═══ TROIS CLAUSES, ET LA TROISIÈME EST CELLE QU'ON OUBLIE ═══
--
--   commence par `/`   sinon c'est une URL absolue
--   pas `//`           `//ailleurs.example` est relatif au PROTOCOLE : le
--                      navigateur y lit un autre domaine
--   pas `/\`           et c'est la subtile : les navigateurs NORMALISENT la
--                      barre inversée en barre oblique. `/\ailleurs.example`
--                      devient `//ailleurs.example` avant même la requête.
--
-- Une garde qui n'écrirait que les deux premières paraîtrait complète et
-- laisserait passer la troisième. Les trois sont éprouvées séparément.
--
-- ═══ LE FLUX SE DÉPENSE UNE FOIS ═══
--
-- `consume_login_flow` rend le vérificateur PKCE, et seulement au premier
-- passage. Le second n'obtient RIEN — pas une erreur : distinguer « déjà
-- consommé » de « n'existe pas » renseignerait qui essaie.
--
-- LA VUE `api.login_flow` A ÉTÉ RETIRÉE au plan applicatif par
-- `a_granted_view_must_open` : elle exposait `code_verifier` et `state`, de quoi
-- terminer l'authentification de quelqu'un d'autre. Le service passe par ces
-- deux fonctions, et par elles seules — ce banc emprunte donc le même chemin.

-- ═══ CE QUE CE BANC TUE, MESURÉ ═══
--
-- Dix objets, soit TOUT ce que la table porte : ses sept contraintes, son index
-- unique, et ses deux fonctions. C'est rare, et l'explication est simple — le
-- flux n'a ni déclencheur ni politique, tout y est forme et unicité, et une
-- forme s'éprouve en écrivant la valeur qu'elle refuse.
--
-- Le compte de la base entière vit dans `packages/harnais/mutation-sql.mjs`.

SET search_path TO pgtap, public;

SELECT plan(20);

-- Quarante-trois caractères : la longueur d'un SHA-256 en base64url, celle
-- qu'exigent `state` et `nonce`.
SELECT is(char_length(repeat('a', 43)), 43, 'the bench agrees with itself on what 43 characters are');

-- ═══════════════════════════════════════════════════════════════════════════
--  LA REDIRECTION
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$SELECT admin.open_login_flow(repeat('s', 43), repeat('n', 43),
                                   repeat('v', 43), '/tableau/incidents')$$,
    'a path inside the site is accepted'
);

SELECT lives_ok(
    $$SELECT admin.open_login_flow(repeat('t', 43), repeat('n', 43),
                                   repeat('v', 43), NULL)$$,
    'and so is no redirection at all'
);

SELECT throws_ok(
    $$SELECT admin.open_login_flow(repeat('u', 43), repeat('n', 43),
                                   repeat('v', 43), 'https://ailleurs.example/')$$,
    '23514', NULL,
    'an absolute URL is refused'
);

-- RELATIF AU PROTOCOLE. `//ailleurs.example` ne commence pas par `http`, il
-- ressemble à un chemin, et le navigateur y lit un autre domaine.
SELECT throws_ok(
    $$SELECT admin.open_login_flow(repeat('u', 43), repeat('n', 43),
                                   repeat('v', 43), '//ailleurs.example/')$$,
    '23514', NULL,
    'so is a protocol-relative one, which only looks like a path'
);

-- LA BARRE INVERSÉE. Les navigateurs la normalisent en barre oblique AVANT
-- d'émettre la requête : `/\ailleurs.example` part comme
-- `//ailleurs.example`. Une garde qui ne connaîtrait que les deux formes
-- précédentes serait contournée par un seul caractère.
SELECT throws_ok(
    $$SELECT admin.open_login_flow(repeat('u', 43), repeat('n', 43),
                                   repeat('v', 43), '/' || chr(92) || 'ailleurs.example/')$$,
    '23514', NULL,
    'and so is a backslash, which the browser turns into the one above'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LES FORMES DU FLUX
--
--  Ce ne sont pas des coquetteries : un `state` court se devine, un
--  vérificateur court se force, et PKCE ne protège plus rien.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$SELECT admin.open_login_flow('trop-court', repeat('n', 43), repeat('v', 43))$$,
    '23514', NULL,
    'an anti-CSRF state shorter than a hash is refused'
);

SELECT throws_ok(
    $$SELECT admin.open_login_flow(repeat('u', 43), 'trop-court', repeat('v', 43))$$,
    '23514', NULL,
    'and so is a short nonce'
);

SELECT throws_ok(
    $$SELECT admin.open_login_flow(repeat('u', 43), repeat('n', 43), repeat('v', 42))$$,
    '23514', NULL,
    'a PKCE verifier below the 43 characters the standard demands is refused'
);

SELECT throws_ok(
    $$SELECT admin.open_login_flow(repeat('u', 43), repeat('n', 43), repeat('v', 129))$$,
    '23514', NULL,
    'and one above the 128 it allows, which no client would honour'
);

SELECT throws_ok(
    $$SELECT admin.open_login_flow(repeat('u', 43), repeat('n', 43),
                                   repeat('v', 43), NULL, 'pas-une-empreinte')$$,
    '23514', NULL,
    'a binding thumbprint that is not one is refused here too'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UN ÉTAT N'EXISTE QU'UNE FOIS
--
--  C'est le jeton anti-CSRF : deux flux qui le partagent laisseraient l'un
--  répondre pour l'autre, et la protection s'annulerait.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$SELECT admin.open_login_flow(repeat('s', 43), repeat('n', 43), repeat('v', 43))$$,
    '23505', NULL,
    'the same anti-CSRF state cannot open two flows'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE FLUX SE DÉPENSE UNE FOIS
-- ═══════════════════════════════════════════════════════════════════════════

-- DEUX VALEURS NON NULLES, ET C'EST DÉLIBÉRÉ. Affirmer qu'un champ vaut NULL
-- ne distingue pas « la fonction a rendu une ligne dont le champ est vide » de
-- « la fonction n'a rien rendu du tout » — l'assertion serait vraie sans rien
-- prouver. On interroge donc le flux qui porte une destination.
SELECT is(
    (SELECT code_verifier FROM admin.consume_login_flow(repeat('s', 43))),
    repeat('v', 43),
    'consuming a flow hands back the PKCE verifier'
);

SELECT is(
    (SELECT nonce FROM admin.consume_login_flow(repeat('t', 43))),
    repeat('n', 43),
    'and the nonce that binds the identity token to this exact flow'
);

-- LA DESTINATION FAIT L'ALLER-RETOUR. C'est le sujet du fichier : la garde ne
-- sert à rien si le chemin qu'elle a validé n'est pas celui qu'on relit.
DO $$ BEGIN
  PERFORM admin.open_login_flow(repeat('x', 43), repeat('n', 43),
                                repeat('v', 43), '/tableau/incidents');
END $$;

SELECT is(
    (SELECT redirect_to FROM admin.consume_login_flow(repeat('x', 43))),
    '/tableau/incidents',
    'and the destination comes back exactly as it was validated'
);

-- LE REJEU. Le code d'autorisation ne s'échange pas deux fois ; sans cela, un
-- code intercepté resterait utilisable après que le légitime s'en soit servi.
SELECT is(
    (SELECT count(*)::int FROM admin.consume_login_flow(repeat('s', 43))),
    0,
    'spending the same flow twice yields nothing'
);

SELECT is(
    (SELECT count(*)::int FROM admin.consume_login_flow(repeat('z', 43))),
    0,
    'and an unknown state is indistinguishable from a spent one'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  DIX MINUTES, PAS PLUS
--
--  Un flux ouvert et jamais terminé reste une porte entrouverte. On l'écrit
--  directement ici : `open_login_flow` fixe l'échéance lui-même, donc c'est le
--  seul moyen d'en fabriquer un périmé.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  INSERT INTO admin.login_flow (state, nonce, code_verifier, created_at, expires_at)
  VALUES (repeat('p', 43), repeat('n', 43), repeat('v', 43),
          now() - interval '20 minutes', now() - interval '10 minutes');
END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.consume_login_flow(repeat('p', 43))),
    0,
    'an expired flow hands back nothing, however well-formed'
);

SELECT throws_ok(
    $$INSERT INTO admin.login_flow (state, nonce, code_verifier, expires_at)
      VALUES (repeat('q', 43), repeat('n', 43), repeat('v', 43),
              now() - interval '1 minute')$$,
    '23514', NULL,
    'and a flow may not be born already expired'
);

SELECT throws_ok(
    $$INSERT INTO admin.login_flow
        (state, nonce, code_verifier, expires_at, created_at, consumed_at)
      VALUES (repeat('r', 43), repeat('n', 43), repeat('v', 43),
              now() + interval '10 minutes', now(), now() - interval '1 hour')$$,
    '23514', NULL,
    'nor consumed before it was opened'
);

SELECT * FROM finish();
