-- CE QUI DISPARAÎT, QUAND, ET CE QUI NE DOIT PAS.
--
-- ═══ DEUX FAÇONS DE SE TROMPER, SYMÉTRIQUES ═══
--
-- Une purge trop large efface ce dont on aura besoin. Une purge trop étroite
-- laisse grossir des tables qui n'ont aucune raison de vivre — et un jeton
-- dépensé qu'on garde éternellement finit par coûter plus cher que le rejeu
-- qu'il empêche.
--
-- Les deux erreurs sont silencieuses : la première se découvre en enquêtant,
-- la seconde en manquant de place. Ce banc éprouve donc les deux bords.
--
-- ═══ LA SUBTILITÉ DE `purge_login_flows` ═══
--
-- Un flux ancien n'est pas forcément mort. Quelqu'un en train de
-- s'authentifier chez le fournisseur d'identité a un flux ouvert depuis
-- plusieurs minutes, et l'effacer le renverrait à la case départ sans
-- explication.
--
-- La fonction ne supprime donc que ce qui est ANCIEN **et** (consommé OU
-- expiré). Trois assertions ci-dessous : le consommé part, l'expiré part, le
-- vivant reste — et c'est la troisième qui compte, parce qu'un « WHERE
-- created_at < … » tout seul paraîtrait suffisant.
--
-- ═══ ET L'ANNEAU D'AUDIT ÉCHOUE BRUYAMMENT ═══
--
-- `purge_challenges` rend zéro quand aucune politique n'est déclarée, et c'est
-- juste pour des défis éphémères. `detach_expired`, lui, LÈVE — parce que le
-- silence y signifierait « la rétention ne tourne plus » sans que personne ne
-- l'apprenne, et un audit qui échoue en silence est le pire des deux.

SET search_path TO pgtap, public;

SELECT plan(14);

-- ─────────────────────────────────────────────────────────────────────────
--  LE MONTAGE
-- ─────────────────────────────────────────────────────────────────────────

DO $$
DECLARE
    u uuid := gen_random_uuid();
BEGIN
    INSERT INTO admin."user" (id) VALUES (u);

    INSERT INTO admin.session (id, user_id, absolute_expires_at)
    VALUES ('0901aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', u, now() + interval '1 hour');

    PERFORM set_config('essai.u', u::text, false);
END $$;

SELECT isnt(
    nullif(current_setting('essai.u', true), ''),
    NULL,
    'the session that will carry the proofs exists'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UNE PREUVE SE DÉPENSE UNE FOIS
-- ═══════════════════════════════════════════════════════════════════════════

SELECT is(
    (SELECT count(*)::int FROM admin.spend_proof(
        '0902aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        '0901aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        now() + interval '15 minutes')),
    1,
    'spending a fresh proof records it'
);

-- LE REJEU DEMANDE UNE TOUTE AUTRE ÉCHÉANCE, et c'est délibéré : c'est la
-- seule façon de distinguer un `ON CONFLICT DO NOTHING` d'un `DO UPDATE`. Les
-- rejouer à l'identique aurait laissé les deux se comporter pareil, et
-- l'assertion suivante n'aurait rien affirmé.
SELECT is(
    (SELECT count(*)::int FROM admin.spend_proof(
        '0902aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        '0901aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        now() + interval '10 years')),
    0,
    'and presenting it a second time gets nothing'
);

-- LA LIGNE N'A PAS BOUGÉ. Si le rejeu repoussait `expires_at`, un attaquant
-- maintiendrait la preuve en vie indéfiniment — et la purge ne la ramasserait
-- jamais.
SELECT ok(
    (SELECT expires_at < now() + interval '1 hour' FROM admin.spent_proof
      WHERE jti = '0902aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
    'and the replay does not push back the window it was first recorded with'
);

SELECT throws_ok(
    $$INSERT INTO admin.spent_proof (jti, session_id, expires_at)
      VALUES (gen_random_uuid(), gen_random_uuid(), now() + interval '15 minutes')$$,
    '23503', NULL,
    'a proof cannot be spent against a session that does not exist'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  ET ELLE NE SE GARDE PAS ÉTERNELLEMENT
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  INSERT INTO admin.spent_proof (jti, session_id, spent_at, expires_at)
  VALUES ('0903aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
          '0901aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
          now() - interval '1 hour', now() - interval '30 minutes');
END $$;

SELECT ok(
    admin.purge_spent_proofs() >= 1,
    'purging removes the proofs whose window has closed'
);

-- ET LAISSE CELLE QUI SERT ENCORE. Une purge qui emporterait les preuves
-- vivantes rouvrirait le rejeu qu'elles ferment.
SELECT is(
    (SELECT count(*)::int FROM admin.spent_proof
      WHERE jti = '0902aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
    1,
    'while the one still guarding against replay stays'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UN FLUX ANCIEN N'EST PAS UN FLUX MORT
--
--  LA PLUS IMPORTANTE DU FICHIER. Un `WHERE created_at < …` tout seul
--  paraîtrait suffisant, et renverrait à la case départ quiconque est en train
--  de s'authentifier.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  -- Ancien ET consommé.
  INSERT INTO admin.login_flow
      (state, nonce, code_verifier, created_at, expires_at, consumed_at)
  VALUES (repeat('c', 43), repeat('n', 43), repeat('v', 43),
          now() - interval '3 days', now() - interval '3 days' + interval '10 minutes',
          now() - interval '3 days');

  -- Ancien ET expiré, jamais consommé.
  INSERT INTO admin.login_flow
      (state, nonce, code_verifier, created_at, expires_at)
  VALUES (repeat('e', 43), repeat('n', 43), repeat('v', 43),
          now() - interval '3 days', now() - interval '3 days' + interval '10 minutes');

  -- Ancien, mais VIVANT : quelqu'un est chez le fournisseur d'identite.
  INSERT INTO admin.login_flow
      (state, nonce, code_verifier, created_at, expires_at)
  VALUES (repeat('l', 43), repeat('n', 43), repeat('v', 43),
          now() - interval '3 days', now() + interval '5 minutes');

  PERFORM admin.purge_login_flows();
END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.login_flow WHERE state = repeat('c', 43)),
    0,
    'an old, spent flow is purged'
);

SELECT is(
    (SELECT count(*)::int FROM admin.login_flow WHERE state = repeat('e', 43)),
    0,
    'so is an old, expired one'
);

SELECT is(
    (SELECT count(*)::int FROM admin.login_flow WHERE state = repeat('l', 43)),
    1,
    'but an old flow that is still live survives — someone is authenticating'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  L'ANNEAU D'AUDIT
-- ═══════════════════════════════════════════════════════════════════════════

-- IDEMPOTENTE. La création des partitions tourne périodiquement ; un second
-- passage ne doit rien créer, et surtout ne doit pas échouer.
SELECT is(
    audit.ensure_partitions(3),
    0,
    'creating the coming partitions a second time creates nothing'
);

-- FERMÉ ET BRUYANT. Sans fenêtre déclarée, rien ne serait jamais détaché et le
-- journal finirait par peser plus que les données qu'il protège. Le silence
-- serait ici la pire réponse.
DO $$ BEGIN
  UPDATE audit.retention SET relation = 'audit.autre_chose'
   WHERE relation = 'audit.event';
END $$;

SELECT throws_ok(
    'SELECT * FROM audit.detach_expired()',
    'XA020', NULL,
    'detaching with no declared window refuses loudly, it does not stay silent'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  ET LES FENÊTRES ELLES-MÊMES ONT UNE FORME
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$UPDATE audit.retention SET keep_for = interval '0'
       WHERE relation = 'audit.autre_chose'$$,
    '23514', NULL,
    'an audit window that keeps nothing for no time is refused'
);

SELECT throws_ok(
    $$DELETE FROM audit.retention WHERE relation = 'audit.autre_chose'$$,
    'XA001', NULL,
    'and the retention rule itself is never deleted'
);

SELECT * FROM finish();
