-- LA PREMIÈRE CLÉ, ET COMMENT ON L'OBTIENT SANS EN AVOIR DÉJÀ UNE.
--
-- ═══ L'ŒUF ET LA POULE DU PLAN DE CONTRÔLE ═══
--
-- Tout ici se signe avec une clé matérielle. Reste à en enrôler une première :
-- un administrateur qui vient d'être déclaré n'a rien pour prouver sa présence,
-- donc rien pour demander le droit d'enrôler.
--
-- Le ticket est la réponse, et c'est LE SEUL MOMENT où le plan accepte un
-- secret partagé. Il porte donc toutes les contraintes qu'on met sur ce qui
-- n'est pas prouvé par du matériel :
--
--   QUINZE MINUTES      un ticket oublié est une porte laissée ouverte
--   UN SEUL VIVANT      par administrateur, et le nouveau révoque l'ancien
--   UNE SEULE FIN       consommé OU révoqué, jamais les deux
--   JAMAIS EN CLAIR     la table garde une empreinte, pas le secret
--
-- ═══ LE SUPERSEDE ÉCRIT, IL NE REFUSE PAS ═══
--
-- Émettre un second ticket ne se heurte pas à l'index unique : `ticket_supersede`
-- révoque le précédent avant l'insertion. C'est ce qu'on veut — un
-- administrateur qui redemande un ticket parce qu'il a perdu le premier ne doit
-- pas se heurter à une erreur, et l'ancien ne doit plus valoir.
--
-- Un banc qui n'affirmerait que des refus laisserait ce comportement survivre.
-- Il est donc affirmé sur son RÉSULTAT.
--
-- ═══ ET LE JOURNAL N'EN GARDE RIEN D'UTILISABLE ═══
--
-- Ni `secret_hash`, ni même l'identifiant du ticket ne figurent dans
-- `audit.auditable_column`. Conséquence que seul un banc de comportement
-- voit : la clé de ligne de l'événement est une EMPREINTE, pas l'identifiant.
-- Un journal qu'on exporte pour analyse ne désigne donc aucun enrôlement en
-- cours.

-- ═══ CE QUE CE BANC TUE, MESURÉ ═══
--
-- Dix objets : les quatre contraintes de forme, les deux déclencheurs, les
-- TROIS fonctions du cycle, et le `zz_audit` de la table — celui-là parce que
-- les deux dernières assertions relisent ce qu'il écrit.
--
-- `uq_ticket_live_per_user` survit, et pour la même raison que
-- `uq_session_mono` : `ticket_supersede` révoque le précédent avant
-- l'insertion, donc l'index n'a jamais rien à refuser en séquentiel. Il ne
-- parle que sur une course.
--
-- Le compte de la base entière vit dans `packages/harnais/mutation-sql.mjs`.

SET search_path TO pgtap, public;

SELECT plan(19);

-- ─────────────────────────────────────────────────────────────────────────
--  LE MONTAGE
-- ─────────────────────────────────────────────────────────────────────────

DO $$
DECLARE
    a uuid := gen_random_uuid();
    b uuid := gen_random_uuid();
    d uuid := gen_random_uuid();
BEGIN
    PERFORM set_config('app.caller', 'banc-du-ticket', false);
    INSERT INTO admin."user" (id) VALUES (a), (b);
    INSERT INTO admin."user" (id, deactivated_at) VALUES (d, now());

    PERFORM set_config('essai.a', a::text, false);
    PERFORM set_config('essai.b', b::text, false);
    PERFORM set_config('essai.d', d::text, false);
END $$;

SELECT isnt(
    nullif(current_setting('essai.a', true), ''),
    NULL,
    'the three accounts of this bench exist'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  ÉMETTRE
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$SELECT admin.issue_enrollment_ticket(
        current_setting('essai.a')::uuid, repeat('h', 43))$$,
    'a ticket is issued'
);

-- QUINZE MINUTES, FIXÉES PAR LA FONCTION. L'appelant ne choisit pas : une
-- fenêtre négociable finirait par se négocier.
SELECT is(
    (SELECT expires_at - created_at FROM admin.enrollment_ticket
      WHERE user_id = current_setting('essai.a')::uuid),
    interval '15 minutes',
    'and lives exactly fifteen minutes, chosen by the schema and not the caller'
);

SELECT throws_ok(
    $$SELECT admin.issue_enrollment_ticket(
        current_setting('essai.d')::uuid, repeat('h', 43))$$,
    'AD121', NULL,
    'a deactivated account is issued no ticket'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LES FORMES
--
--  Écrites en direct : `issue_enrollment_ticket` pose lui-même l'échéance, donc
--  c'est le seul moyen d'éprouver les bornes qu'il respecte.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$INSERT INTO admin.enrollment_ticket (user_id, secret_hash, expires_at)
      VALUES (current_setting('essai.b')::uuid, repeat('h', 43),
              now() + interval '16 minutes')$$,
    '23514', NULL,
    'a window wider than fifteen minutes is refused'
);

SELECT throws_ok(
    $$INSERT INTO admin.enrollment_ticket (user_id, secret_hash, expires_at)
      VALUES (current_setting('essai.b')::uuid, repeat('h', 43),
              now() - interval '1 minute')$$,
    '23514', NULL,
    'and so is a ticket born already expired'
);

-- L'EMPREINTE FAIT QUARANTE-TROIS CARACTÈRES — un SHA-256 en base64url. Plus
-- court, ce n'est pas une empreinte : c'est un secret qu'on a rangé tel quel.
SELECT throws_ok(
    $$INSERT INTO admin.enrollment_ticket (user_id, secret_hash, expires_at)
      VALUES (current_setting('essai.b')::uuid, 'secret-en-clair',
              now() + interval '10 minutes')$$,
    '23514', NULL,
    'a secret that is not a hash of the right length is refused'
);

SELECT throws_ok(
    $$INSERT INTO admin.enrollment_ticket
        (user_id, secret_hash, expires_at, consumed_at, revoked_at)
      VALUES (current_setting('essai.b')::uuid, repeat('h', 43),
              now() + interval '10 minutes', now(), now())$$,
    '23514', NULL,
    'a ticket ends once — consumed or revoked, never both'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE SECOND TICKET RÉVOQUE LE PREMIER
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  PERFORM admin.issue_enrollment_ticket(
      current_setting('essai.a')::uuid, repeat('i', 43));
END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.enrollment_ticket
      WHERE user_id = current_setting('essai.a')::uuid
        AND secret_hash = repeat('h', 43)
        AND revoked_at IS NOT NULL),
    1,
    'asking for a second ticket revokes the first rather than refusing'
);

SELECT is(
    (SELECT count(*)::int FROM admin.enrollment_ticket
      WHERE user_id = current_setting('essai.a')::uuid
        AND consumed_at IS NULL AND revoked_at IS NULL),
    1,
    'so one administrator never holds two live tickets'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  CONSOMMER
-- ═══════════════════════════════════════════════════════════════════════════

SELECT ok(
    admin.ticket_is_open(current_setting('essai.a')::uuid, repeat('i', 43)),
    'the live ticket answers that it is open'
);

-- ET L'ANCIEN NE RÉPOND PLUS, alors qu'il existe encore : la révocation n'est
-- pas une suppression, elle est une date.
SELECT ok(
    NOT admin.ticket_is_open(current_setting('essai.a')::uuid, repeat('h', 43)),
    'while the revoked one does not, though its row is still there'
);

SELECT is(
    (SELECT count(*)::int FROM admin.consume_enrollment_ticket(
        current_setting('essai.a')::uuid, repeat('i', 43))),
    1,
    'consuming the live ticket succeeds, once'
);

SELECT is(
    (SELECT count(*)::int FROM admin.consume_enrollment_ticket(
        current_setting('essai.a')::uuid, repeat('i', 43))),
    0,
    'and the second attempt gets nothing — a ticket is spent once'
);

-- LE MAUVAIS SECRET REND LA MÊME CHOSE QUE LE BON DÉJÀ DÉPENSÉ : rien.
-- Distinguer les deux dirait à qui essaie s'il a trouvé le bon secret.
SELECT is(
    (SELECT count(*)::int FROM admin.consume_enrollment_ticket(
        current_setting('essai.a')::uuid, repeat('z', 43))),
    0,
    'a wrong secret is indistinguishable from a spent ticket'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE TEMPS ET LA RÉVOCATION FERMENT AUSSI
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  INSERT INTO admin.enrollment_ticket
      (user_id, secret_hash, created_at, expires_at)
  VALUES (current_setting('essai.b')::uuid, repeat('j', 43),
          now() - interval '20 minutes', now() - interval '10 minutes');
END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.consume_enrollment_ticket(
        current_setting('essai.b')::uuid, repeat('j', 43))),
    0,
    'an expired ticket opens nothing, however correct its secret'
);

SELECT is(
    (SELECT count(*)::int FROM admin.consume_enrollment_ticket(
        current_setting('essai.a')::uuid, repeat('h', 43))),
    0,
    'nor does a revoked one'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  CE QUE LE JOURNAL EN RETIENT
--
--  DEUX MASQUAGES, PAS UN. Le secret évidemment — mais aussi l'IDENTIFIANT du
--  ticket, absent lui aussi du registre des colonnes auditables. La clé de
--  ligne de l'événement est donc une empreinte : un journal qu'on exporte ne
--  désigne aucun enrôlement en cours.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT is(
    (SELECT changed -> 'secret_hash' FROM audit.event
      WHERE table_name = 'enrollment_ticket' AND op = 'INSERT'
      ORDER BY event_id LIMIT 1),
    '{"redacted": true}'::jsonb,
    'the journal records the ticket secret as redacted'
);

SELECT ok(
    (SELECT row_key ->> 'id' LIKE 'sha256:%' FROM audit.event
      WHERE table_name = 'enrollment_ticket' AND op = 'INSERT'
      ORDER BY event_id LIMIT 1),
    'and names the ticket by a hash, never by the identifier itself'
);

SELECT * FROM finish();
