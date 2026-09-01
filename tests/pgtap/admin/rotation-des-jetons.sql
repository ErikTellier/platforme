-- LE REJEU D'UN JETON DE RAFRAÎCHISSEMENT.
--
-- ═══ L'INVARIANT QUE CE FICHIER DÉFEND ═══
--
-- Un jeton de rafraîchissement se dépense UNE FOIS. Présenté deux fois, le
-- second passage n'obtient rien — pas une erreur, RIEN. C'est l'attaque la plus
-- banale contre un plan de contrôle : on vole une paire, et on la rejoue.
--
-- ═══ POURQUOI « RIEN » ET NON « ERREUR » ═══
--
-- `rotate_pair` rend ZÉRO LIGNE quand la rotation n'aboutit pas, quelle qu'en
-- soit la raison — déjà dépensé, session close, plafond atteint, inactivité
-- dépassée. Un code d'erreur distinct par cause dirait à l'attaquant LAQUELLE
-- de ses hypothèses était juste.
--
-- Conséquence pour ce banc : la plupart des assertions comptent des lignes au
-- lieu d'attendre un `throws_ok`. Un banc qui n'affirmerait que des refus ne
-- verrait rien ici — et c'est précisément ce qui laissait ces objets survivre.
--
-- ═══ LA ROTATION EST LA LATENCE DE RÉVOCATION ═══
--
-- `pair_emission_guard` relit `active_user` À CHAQUE ÉMISSION, et
-- `validate_bearer` à chaque validation. Ce n'est pas une vérification en trop :
-- c'est ce qui fait qu'un administrateur désactivé est arrêté au prochain appel
-- plutôt qu'au plafond horaire de sa session. Tourner souvent, c'est révoquer
-- vite — et deux assertions ci-dessous tiennent cette propriété en place.
--
-- ═══ TROIS UNICITÉS, TROIS CHOSES DIFFÉRENTES ═══
--
--   uq_pair_bearer            un `jti` de porteur n'existe qu'une fois AU MONDE
--   uq_pair_refresh           idem pour le rafraîchissement
--   uq_pair_live_per_session  une seule paire VIVANTE par session
--
-- Les deux premières empêchent l'ambiguïté à la vérification ; la troisième
-- empêche deux porteurs valides en même temps, donc un accès qui survit à la
-- rotation qui devait le remplacer.
--
-- ═══ CE QUE CE BANC TUE, MESURÉ ═══
--
-- Neuf objets, et DEUX FONCTIONS — ce que seul un banc qui appelle peut faire :
--
--   fonction      admin.rotate_pair, admin.validate_bearer
--   déclencheur   pair_emission_guard, no_delete_pair
--   index         uq_pair_bearer, uq_pair_refresh, uq_pair_live_per_session
--   contrainte    pair_inactivity_after_issue
--   politique     owner_is_the_vetted_path sur token_pair
--
-- La dernière est un tué PAR DÉPENDANCE : la retirer aveugle `rotate_pair`, qui
-- s'exécute comme `admin_owner`. Aucune assertion ne la nomme.
--
-- Le compte de la base entière vit dans `packages/harnais/mutation-sql.mjs`.
--
-- ═══ LE MONTAGE ═══
--
--   U  un administrateur, sa session
--   D  un compte qu'on désactivera EN COURS DE ROUTE

SET search_path TO pgtap, public;

SELECT plan(23);

-- ─────────────────────────────────────────────────────────────────────────
--  LE MONTAGE
-- ─────────────────────────────────────────────────────────────────────────

DO $$
DECLARE
    u uuid := gen_random_uuid();
    d uuid := gen_random_uuid();
BEGIN
    INSERT INTO admin."user" (id) VALUES (u), (d);

    INSERT INTO admin.session (id, user_id, absolute_expires_at)
    VALUES ('cccc1111-1111-4111-8111-111111111111', u, now() + interval '1 hour'),
           ('cccc2222-2222-4222-8222-222222222222', d, now() + interval '1 hour');

    PERFORM set_config('essai.u', u::text, false);
    PERFORM set_config('essai.d', d::text, false);
END $$;

SELECT isnt(
    nullif(current_setting('essai.u', true), ''),
    NULL,
    'the two sessions of this bench exist'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  ÉMETTRE UNE PAIRE
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO admin.token_pair
        (id, session_id, jti_bearer, jti_refresh, inactivity_expires_at)
      VALUES ('dddd1111-1111-4111-8111-111111111111',
              'cccc1111-1111-4111-8111-111111111111',
              '11111111-1111-4111-8111-111111111111',
              '22222222-2222-4222-8222-222222222222',
              now() + interval '15 minutes')$$,
    'a token pair is issued for a live session'
);

-- UNE PAIRE DONT LES DEUX JETONS SONT LE MÊME N'EST PAS UNE PAIRE : le porteur
-- serait son propre rafraîchissement, et dépenser l'un dépenserait l'autre.
SELECT throws_ok(
    $$INSERT INTO admin.token_pair
        (session_id, jti_bearer, jti_refresh, inactivity_expires_at)
      VALUES ('cccc1111-1111-4111-8111-111111111111',
              '33333333-3333-4333-8333-333333333333',
              '33333333-3333-4333-8333-333333333333',
              now() + interval '15 minutes')$$,
    'AD002', NULL,
    'a pair whose two tokens are the same is not a pair'
);

-- UNE SESSION QUI N'EXISTE PAS, NOMMÉE PAR SON NOM. Le déclencheur parle avant
-- la clé étrangère : sans lui, toutes les variables resteraient nulles et le
-- refus sortirait sous « l'administrateur est désactivé », qui désigne autre
-- chose.
SELECT throws_ok(
    $$INSERT INTO admin.token_pair
        (session_id, jti_bearer, jti_refresh, inactivity_expires_at)
      VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
              now() + interval '15 minutes')$$,
    'AD012', NULL,
    'a pair for a session that does not exist is refused, by its real cause'
);

-- L'INACTIVITÉ NE DÉPASSE PAS LE PLAFOND DE LA SESSION. Sans quoi la fenêtre
-- glissante repousserait la limite absolue qu'elle est censée respecter.
SELECT throws_ok(
    $$INSERT INTO admin.token_pair
        (session_id, jti_bearer, jti_refresh, inactivity_expires_at)
      VALUES ('cccc1111-1111-4111-8111-111111111111',
              gen_random_uuid(), gen_random_uuid(),
              now() + interval '2 hours')$$,
    'AD013', NULL,
    'the inactivity window may not outlast the session ceiling'
);

SELECT throws_ok(
    $$INSERT INTO admin.token_pair
        (session_id, jti_bearer, jti_refresh, inactivity_expires_at)
      VALUES ('cccc1111-1111-4111-8111-111111111111',
              gen_random_uuid(), gen_random_uuid(),
              now() - interval '1 minute')$$,
    '23514', NULL,
    'nor expire before it was issued'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  TROIS UNICITÉS
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$INSERT INTO admin.token_pair
        (session_id, jti_bearer, jti_refresh, inactivity_expires_at)
      VALUES ('cccc2222-2222-4222-8222-222222222222',
              '11111111-1111-4111-8111-111111111111',
              gen_random_uuid(), now() + interval '15 minutes')$$,
    '23505', NULL,
    'a bearer identifier exists once in the whole base, not once per session'
);

SELECT throws_ok(
    $$INSERT INTO admin.token_pair
        (session_id, jti_bearer, jti_refresh, inactivity_expires_at)
      VALUES ('cccc2222-2222-4222-8222-222222222222',
              gen_random_uuid(),
              '22222222-2222-4222-8222-222222222222',
              now() + interval '15 minutes')$$,
    '23505', NULL,
    'and so does a refresh identifier'
);

-- DEUX PORTEURS VALIDES EN MÊME TEMPS, c'est un accès qui survit à la rotation
-- censée le remplacer.
SELECT throws_ok(
    $$INSERT INTO admin.token_pair
        (session_id, jti_bearer, jti_refresh, inactivity_expires_at)
      VALUES ('cccc1111-1111-4111-8111-111111111111',
              gen_random_uuid(), gen_random_uuid(),
              now() + interval '15 minutes')$$,
    '23505', NULL,
    'one session holds at most one live pair'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE PORTEUR SE VALIDE
-- ═══════════════════════════════════════════════════════════════════════════

SELECT is(
    (SELECT user_id FROM admin.validate_bearer('11111111-1111-4111-8111-111111111111')),
    current_setting('essai.u')::uuid,
    'a live bearer validates, and names its administrator'
);

-- LE PLUS TÔT DES DEUX. La fenêtre d'inactivité et le plafond de session
-- bornent chacun la validité ; retenir la plus lointaine reviendrait à ignorer
-- l'autre.
SELECT ok(
    (SELECT valid_until FROM admin.validate_bearer('11111111-1111-4111-8111-111111111111'))
      <= (SELECT absolute_expires_at FROM admin.session
           WHERE id = 'cccc1111-1111-4111-8111-111111111111'),
    'and never past the ceiling of the session it belongs to'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA ROTATION
-- ═══════════════════════════════════════════════════════════════════════════

SELECT is(
    (SELECT count(*)::int FROM admin.rotate_pair(
        '22222222-2222-4222-8222-222222222222',
        '44444444-4444-4444-8444-444444444444',
        '55555555-5555-4555-8555-555555555555')),
    1,
    'spending a refresh token mints exactly one new pair'
);

SELECT is(
    (SELECT replaced_at IS NOT NULL FROM admin.token_pair
      WHERE id = 'dddd1111-1111-4111-8111-111111111111'),
    true,
    'and marks the spent one as replaced, in the same act'
);

-- L'ANCIEN PORTEUR NE VAUT PLUS RIEN. Sans cela, la rotation ajouterait un
-- accès au lieu de le remplacer.
SELECT is(
    (SELECT count(*)::int FROM admin.validate_bearer('11111111-1111-4111-8111-111111111111')),
    0,
    'the bearer of the spent pair stops validating immediately'
);

SELECT is(
    (SELECT count(*)::int FROM admin.validate_bearer('44444444-4444-4444-8444-444444444444')),
    1,
    'and the new one takes over'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE REJEU
--
--  LE CŒUR DU FICHIER. Le même rafraîchissement, une seconde fois.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT is(
    (SELECT count(*)::int FROM admin.rotate_pair(
        '22222222-2222-4222-8222-222222222222',
        '66666666-6666-4666-8666-666666666666',
        '77777777-7777-4777-8777-777777777777')),
    0,
    'replaying a refresh token already spent yields nothing'
);

-- ET RIEN N'A ÉTÉ ÉMIS. « Zéro ligne rendue » ne dirait pas si une paire avait
-- quand même été écrite avant que la requête ne renonce.
SELECT is(
    (SELECT count(*)::int FROM admin.token_pair
      WHERE jti_bearer = '66666666-6666-4666-8666-666666666666'),
    0,
    'and mints nothing — zero rows returned would not prove that alone'
);

-- UN RAFRAÎCHISSEMENT INCONNU REND LA MÊME CHOSE : rien. Distinguer « déjà
-- dépensé » de « n'a jamais existé » dirait à l'attaquant laquelle de ses
-- hypothèses était juste.
SELECT is(
    (SELECT count(*)::int FROM admin.rotate_pair(
        gen_random_uuid(), gen_random_uuid(), gen_random_uuid())),
    0,
    'an unknown refresh token is indistinguishable from a spent one'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UNE SESSION CLOSE N'ÉMET PLUS
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  UPDATE admin.session SET ended_at = now(), end_reason = 'LOGOUT'
   WHERE id = 'cccc1111-1111-4111-8111-111111111111';
END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.rotate_pair(
        '55555555-5555-4555-8555-555555555555',
        gen_random_uuid(), gen_random_uuid())),
    0,
    'a closed session rotates nothing more'
);

SELECT is(
    (SELECT count(*)::int FROM admin.validate_bearer('44444444-4444-4444-8444-444444444444')),
    0,
    'and its live bearer stops validating the moment the session ends'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA RÉVOCATION MORD AU PROCHAIN APPEL
--
--  C'EST LA PROPRIÉTÉ QUI JUSTIFIE DE TOURNER SOUVENT. Une session ouverte il y
--  a une heure ne dit rien d'une désactivation décidée depuis ; relire
--  `active_user` à chaque émission et à chaque validation transforme la
--  fréquence de rotation en latence de révocation.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  INSERT INTO admin.token_pair
      (session_id, jti_bearer, jti_refresh, inactivity_expires_at)
  VALUES ('cccc2222-2222-4222-8222-222222222222',
          '88888888-8888-4888-8888-888888888888',
          '99999999-9999-4999-8999-999999999999',
          now() + interval '15 minutes');

  UPDATE admin."user" SET deactivated_at = now()
   WHERE id = current_setting('essai.d')::uuid;
END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.validate_bearer('88888888-8888-4888-8888-888888888888')),
    0,
    'a bearer issued before a deactivation stops validating right after it'
);

SELECT throws_ok(
    $$INSERT INTO admin.token_pair
        (session_id, jti_bearer, jti_refresh, inactivity_expires_at)
      VALUES ('cccc2222-2222-4222-8222-222222222222',
              gen_random_uuid(), gen_random_uuid(),
              now() + interval '15 minutes')$$,
    'AD003', NULL,
    'and a deactivated administrator is issued no new pair'
);

SELECT throws_ok(
    $$DELETE FROM admin.token_pair
       WHERE id = 'dddd1111-1111-4111-8111-111111111111'$$,
    'AD040', NULL,
    'a spent pair is never deleted — it is the trace of what was issued'
);

SELECT * FROM finish();
