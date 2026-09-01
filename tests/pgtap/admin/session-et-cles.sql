-- CE QU'UNE SESSION AUTORISE, ET JUSQU'À QUAND.
--
-- ═══ L'INVARIANT QUE CE FICHIER DÉFEND ═══
--
-- Une clé ne survit pas à la session qui l'a autorisée, et une session ne dure
-- pas plus d'une heure. Tout le reste du plan de contrôle s'appuie là-dessus :
-- révoquer un administrateur ne sert à rien si sa clé continue de signer, et
-- une session sans plafond transforme une compromission d'un instant en accès
-- permanent.
--
-- ═══ DEUX GARDES QUI NE REFUSENT PAS — ELLES CORRIGENT ═══
--
-- La plupart des gardes de ce schéma disent non. Celles-ci écrivent, et c'est
-- ce qui les rend faciles à casser sans s'en apercevoir :
--
--   session_supersede    ouvrir une seconde session ne REFUSE pas la première,
--                        elle la FERME, sous le motif `SUPERSEDED`.
--   key_bounds_guard     `signs_until` n'est pas vérifié, il est ÉCRASÉ par le
--                        plafond de la session. Une clé qui demande moins
--                        obtient quand même le plafond.
--
-- Un banc qui n'affirmerait que des refus les laisserait toutes deux
-- survivre : les transformer en `RAISE` passerait inaperçu, et casserait les
-- appelants en production. Les deux comportements sont donc affirmés sur leur
-- RÉSULTAT, pas sur leur absence d'erreur.
--
-- ═══ MONO-SESSION : UN DÉCLENCHEUR ET UN INDEX, POUR LA MÊME RÈGLE ═══
--
-- `session_supersede` ferme la précédente AVANT l'insertion. `uq_session_mono`
-- interdit deux sessions vivantes pour un même administrateur. Le second ne
-- devrait donc jamais parler — sauf sur une COURSE : un déclencheur ne voit que
-- les lignes validées, donc deux connexions simultanées passeraient toutes deux
-- le déclencheur, et c'est le moteur qui tranche.
--
-- L'index est ici le garde-fou de ce que le déclencheur ne peut pas voir. Le
-- banc ne peut pas fabriquer la course ; il vérifie que le déclencheur fait son
-- travail, et `doctrine.sql` que l'index existe toujours.
--
-- ═══ CE QUE CE BANC TUE, MESURÉ ═══
--
-- Seize objets, et la famille `contrainte` double presque — de 7 tués à 14 :
--
--   contrainte    session_ceiling_bounded, session_absolute_after_creation,
--                 session_cnf_jkt_shape, session_end_coherent,
--                 session_end_reason_fkey, key_activation_coherent,
--                 fk_key_session
--   déclencheur   session_supersede, session_emission_guard,
--                 session_binding_is_immutable, no_delete_session,
--                 key_bounds_guard, key_guard, no_delete_key
--   index         uq_key_kid, uq_key_one_active_per_session_purpose
--
-- `uq_session_mono` SURVIT, et c'est explicable : `session_supersede` ferme la
-- session précédente avant l'insertion, donc l'index n'a jamais rien à refuser.
-- Il ne parle que sur une COURSE, que ce banc ne sait pas fabriquer — un
-- déclencheur ne voit que les lignes validées, deux connexions simultanées
-- passeraient donc toutes deux. Le retirer ne change rien à ce qu'on peut
-- écrire séquentiellement, et `doctrine.sql` veille à ce qu'il existe encore.
--
-- Le compte de la base entière vit dans `packages/harnais/mutation-sql.mjs`.
--
-- ═══ LE MONTAGE ═══
--
--   U  un administrateur ordinaire
--   V  un second, pour les clés qui traversent les sessions
--   D  un compte DÉSACTIVÉ

SET search_path TO pgtap, public;

SELECT plan(26);

-- ─────────────────────────────────────────────────────────────────────────
--  LE MONTAGE
-- ─────────────────────────────────────────────────────────────────────────

DO $$
DECLARE
    u uuid := gen_random_uuid();
    v uuid := gen_random_uuid();
    d uuid := gen_random_uuid();
BEGIN
    INSERT INTO admin."user" (id) VALUES (u), (v);
    INSERT INTO admin."user" (id, deactivated_at) VALUES (d, now());

    PERFORM set_config('essai.u', u::text, false);
    PERFORM set_config('essai.v', v::text, false);
    PERFORM set_config('essai.d', d::text, false);
END $$;

SELECT isnt(
    nullif(current_setting('essai.u', true), ''),
    NULL,
    'the three accounts of this bench exist'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  OUVRIR UNE SESSION
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO admin.session (id, user_id, absolute_expires_at)
      VALUES ('aaaa1111-1111-4111-8111-111111111111',
              current_setting('essai.u')::uuid, now() + interval '1 hour')$$,
    'a session is opened'
);

-- UNE HEURE EST UNE HEURE. Le plafond n'est pas une valeur par défaut que
-- l'appelant peut repousser : c'est la durée maximale d'une compromission.
SELECT throws_ok(
    $$INSERT INTO admin.session (user_id, absolute_expires_at)
      VALUES (current_setting('essai.v')::uuid, now() + interval '61 minutes')$$,
    '23514', NULL,
    'a session may not be granted more than one hour'
);

SELECT throws_ok(
    $$INSERT INTO admin.session (user_id, absolute_expires_at)
      VALUES (current_setting('essai.v')::uuid, now() - interval '1 minute')$$,
    '23514', NULL,
    'nor a ceiling that has already passed'
);

-- UN COMPTE DÉSACTIVÉ N'OUVRE RIEN. La désactivation serait sans effet si elle
-- ne mordait qu'au prochain redémarrage du service.
SELECT throws_ok(
    $$INSERT INTO admin.session (user_id, absolute_expires_at)
      VALUES (current_setting('essai.d')::uuid, now() + interval '1 hour')$$,
    'AD001', NULL,
    'a deactivated account opens no session'
);

-- L'EMPREINTE DE LIAISON A UNE FORME. Quarante-trois caractères en base64url :
-- c'est un SHA-256. Autre chose n'est pas une empreinte, c'est une chaîne que
-- quelqu'un a tapée.
SELECT throws_ok(
    $$INSERT INTO admin.session (user_id, absolute_expires_at, cnf_jkt)
      VALUES (current_setting('essai.v')::uuid, now() + interval '1 hour', 'trop-court')$$,
    '23514', NULL,
    'a binding thumbprint that is not one is refused'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  MONO-SESSION : LA SECONDE FERME LA PREMIÈRE
--
--  LE COMPORTEMENT, PAS SON ABSENCE. `session_supersede` écrit ; le transformer
--  en refus passerait ce banc s'il ne regardait que les erreurs.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO admin.session (id, user_id, absolute_expires_at)
      VALUES ('aaaa2222-2222-4222-8222-222222222222',
              current_setting('essai.u')::uuid, now() + interval '1 hour')$$,
    'opening a second session is allowed'
);

SELECT is(
    (SELECT end_reason FROM admin.session
      WHERE id = 'aaaa1111-1111-4111-8111-111111111111'),
    'SUPERSEDED',
    'because it closed the first, under SUPERSEDED and not some generic reason'
);

SELECT is(
    (SELECT count(*)::int FROM admin.session
      WHERE user_id = current_setting('essai.u')::uuid AND ended_at IS NULL),
    1,
    'one administrator, one live session — never two'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  CE QU'UNE SESSION NE LAISSE PAS RÉÉCRIRE
-- ═══════════════════════════════════════════════════════════════════════════

-- RELIER UNE SESSION À UNE AUTRE CLÉ, c'est légitimer rétroactivement tous les
-- jetons déjà émis contre elle.
SELECT throws_ok(
    $$UPDATE admin.session SET cnf_jkt = repeat('a', 43)
       WHERE id = 'aaaa2222-2222-4222-8222-222222222222'$$,
    'AD014', NULL,
    'the binding key of a session is immutable'
);

-- UNE FIN SANS MOTIF. « Terminée » ne dit pas si l'administrateur est parti,
-- si l'heure a sonné, ou si l'on a coupé.
SELECT throws_ok(
    $$UPDATE admin.session SET ended_at = now()
       WHERE id = 'aaaa2222-2222-4222-8222-222222222222'$$,
    '23514', NULL,
    'a session that ends says why'
);

-- ET LE MOTIF VIENT DU VOCABULAIRE. Un texte libre ne se compte pas, ne
-- s'alerte pas, et se relit mal six mois plus tard.
SELECT throws_ok(
    $$UPDATE admin.session SET ended_at = now(), end_reason = 'PARCE_QUE'
       WHERE id = 'aaaa2222-2222-4222-8222-222222222222'$$,
    '23503', NULL,
    'and the reason comes from the vocabulary, not from prose'
);

SELECT throws_ok(
    $$DELETE FROM admin.session
       WHERE id = 'aaaa2222-2222-4222-8222-222222222222'$$,
    'AD040', NULL,
    'a session is never deleted, only dated'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UNE CLÉ NE SURVIT PAS À SA SESSION
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO akeys.key
        (id, kid, user_id, session_id, public_jwk, kms_ref,
         activated_at, signs_until, published_until, purpose, state)
      VALUES ('bbbb1111-1111-4111-8111-111111111111', gen_random_uuid(),
              current_setting('essai.u')::uuid,
              'aaaa2222-2222-4222-8222-222222222222',
              '{"kty":"EC"}'::jsonb, 'kms://banc',
              now(), now() + interval '30 minutes',
              now() + interval '40 minutes', 'COMMAND', 'ACTIVE')$$,
    'a key is issued against a live session'
);

-- ═══ LE PLAFOND EST ÉCRASÉ, PAS VÉRIFIÉ ═══
--
-- La clé ci-dessus a demandé trente minutes. Elle en reçoit soixante — celles
-- de sa session, à la milliseconde près. C'est délibéré : « une clé vit
-- exactement aussi longtemps que sa session » évite toute la classe de bogues
-- où deux durées calculées à quelques millisecondes d'écart divergent.
--
-- Transformer cette écriture en refus casserait tous les appelants qui
-- demandent moins, et aucun test de refus ne le verrait.
SELECT is(
    (SELECT k.signs_until = s.absolute_expires_at
       FROM akeys.key k JOIN admin.session s ON s.id = k.session_id
      WHERE k.id = 'bbbb1111-1111-4111-8111-111111111111'),
    true,
    'a key that asked for less still gets exactly its session ceiling'
);

-- ET LA PUBLICATION GARDE SES DIX MINUTES DE GRÂCE au-dessus, pour que les
-- jetons déjà émis restent vérifiables le temps qu'ils expirent.
SELECT is(
    (SELECT published_until - signs_until FROM akeys.key
      WHERE id = 'bbbb1111-1111-4111-8111-111111111111'),
    interval '10 minutes',
    'and stays verifiable ten minutes after it stops signing'
);

-- DEMANDER PLUS QUE LA SESSION EST UN REFUS, PAS UN ÉCRÊTAGE. Écrêter en
-- silence cacherait le bogue de l'appelant.
SELECT throws_ok(
    $$INSERT INTO akeys.key
        (kid, user_id, session_id, public_jwk, kms_ref,
         signs_until, published_until, purpose)
      VALUES (gen_random_uuid(), current_setting('essai.u')::uuid,
              'aaaa2222-2222-4222-8222-222222222222',
              '{"kty":"EC"}'::jsonb, 'kms://banc',
              now() + interval '2 hours', now() + interval '3 hours', 'COMMAND')$$,
    'AD022', NULL,
    'a key may not outlive the session that authorised it'
);

-- UNE SESSION QUI N'EXISTE PAS. Le déclencheur parle AVANT la clé étrangère,
-- et il le fait exprès : sans lui, le plafond resterait nul et l'erreur
-- parlerait d'un NOT NULL sans rapport.
SELECT throws_ok(
    $$INSERT INTO akeys.key
        (kid, user_id, session_id, public_jwk, kms_ref,
         signs_until, published_until, purpose)
      VALUES (gen_random_uuid(), current_setting('essai.u')::uuid,
              gen_random_uuid(), '{"kty":"EC"}'::jsonb, 'kms://banc',
              now() + interval '10 minutes', now() + interval '20 minutes', 'COMMAND')$$,
    'AD022', NULL,
    'a key issued against a session that does not exist is refused, by name'
);

-- LA SESSION D'UN AUTRE. La clé étrangère est COMPOSITE — (session_id, user_id)
-- — sinon une clé pourrait revendiquer l'administrateur A en pointant la
-- session de B, et l'attribution deviendrait négociable.
SELECT throws_ok(
    $$INSERT INTO akeys.key
        (kid, user_id, session_id, public_jwk, kms_ref,
         signs_until, published_until, purpose)
      VALUES (gen_random_uuid(), current_setting('essai.v')::uuid,
              'aaaa2222-2222-4222-8222-222222222222',
              '{"kty":"EC"}'::jsonb, 'kms://banc',
              now() + interval '10 minutes', now() + interval '20 minutes', 'COMMAND')$$,
    '23503', NULL,
    'a key may not claim one admin while pointing at another''s session'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UNE CLÉ NE REVIENT PAS EN ARRIÈRE
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$UPDATE akeys.key SET state = 'PENDING'
       WHERE id = 'bbbb1111-1111-4111-8111-111111111111'$$,
    'AD021', NULL,
    'an active key cannot revert to pending'
);

SELECT throws_ok(
    $$INSERT INTO akeys.key
        (kid, user_id, session_id, public_jwk, kms_ref,
         signs_until, published_until, purpose, state)
      VALUES (gen_random_uuid(), current_setting('essai.u')::uuid,
              'aaaa2222-2222-4222-8222-222222222222',
              '{"kty":"EC"}'::jsonb, 'kms://banc',
              now() + interval '10 minutes', now() + interval '20 minutes',
              'COMMAND', 'ACTIVE')$$,
    '23514', NULL,
    'a key cannot be ACTIVE without saying when it was activated'
);

-- LA DESTRUCTION DE LA PRIVÉE EST UN FAIT DATÉ, posé une fois. La reposter
-- déplacerait le moment où la clé a cessé d'exister.
DO $$ BEGIN
  UPDATE akeys.key SET private_destroyed_at = now()
   WHERE id = 'bbbb1111-1111-4111-8111-111111111111';
END $$;

SELECT throws_ok(
    $$UPDATE akeys.key SET private_destroyed_at = now() + interval '1 hour'
       WHERE id = 'bbbb1111-1111-4111-8111-111111111111'$$,
    'AD021', NULL,
    'the destruction of a private key is dated once, never re-dated'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UNE SEULE CLÉ VIVE PAR SESSION ET PAR USAGE
--
--  L'index ne compte que les ACTIVE dont la privée existe encore. Celle du
--  dessus vient d'être détruite, donc la place est libre — et c'est exactement
--  ce que la rotation fait.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO akeys.key
        (id, kid, user_id, session_id, public_jwk, kms_ref,
         activated_at, signs_until, published_until, purpose, state)
      VALUES ('bbbb2222-2222-4222-8222-222222222222', gen_random_uuid(),
              current_setting('essai.u')::uuid,
              'aaaa2222-2222-4222-8222-222222222222',
              '{"kty":"EC"}'::jsonb, 'kms://banc',
              now(), now() + interval '10 minutes',
              now() + interval '20 minutes', 'COMMAND', 'ACTIVE')$$,
    'destroying a private key frees the slot for its successor'
);

SELECT throws_ok(
    $$INSERT INTO akeys.key
        (kid, user_id, session_id, public_jwk, kms_ref,
         activated_at, signs_until, published_until, purpose, state)
      VALUES (gen_random_uuid(), current_setting('essai.u')::uuid,
              'aaaa2222-2222-4222-8222-222222222222',
              '{"kty":"EC"}'::jsonb, 'kms://banc',
              now(), now() + interval '10 minutes',
              now() + interval '20 minutes', 'COMMAND', 'ACTIVE')$$,
    '23505', NULL,
    'but two live keys for the same session and purpose are refused'
);

-- L'IDENTIFIANT DE CLÉ EST UNIQUE PARTOUT. C'est lui que porte l'en-tête d'un
-- jeton : deux clés qui le partagent rendent la vérification ambiguë.
SELECT throws_ok(
    $$INSERT INTO akeys.key
        (kid, user_id, session_id, public_jwk, kms_ref,
         signs_until, published_until, purpose)
      VALUES ((SELECT kid FROM akeys.key WHERE id = 'bbbb2222-2222-4222-8222-222222222222'),
              current_setting('essai.u')::uuid,
              'aaaa2222-2222-4222-8222-222222222222',
              '{"kty":"EC"}'::jsonb, 'kms://banc',
              now() + interval '10 minutes', now() + interval '20 minutes', 'SESSION')$$,
    '23505', NULL,
    'no two keys share the identifier a token header carries'
);

SELECT throws_ok(
    $$DELETE FROM akeys.key WHERE id = 'bbbb2222-2222-4222-8222-222222222222'$$,
    'AD040', NULL,
    'a key is never deleted, only dated'
);

SELECT * FROM finish();
