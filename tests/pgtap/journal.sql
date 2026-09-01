-- LE JOURNAL, ET CE QU'IL N'A PAS LE DROIT DE CONTENIR.
--
-- ═══ POURQUOI CE FICHIER EST À LA RACINE, ET NON DANS admin/ ═══
--
-- `audit.record()` est le même code pour tout service : le registre de ce qui
-- est surveillé est une table, pas une liste écrite en dur. Ces assertions
-- valent donc pour toute base migrée, et se joueront telles quelles contre le
-- deuxième service le jour où il existera.
--
-- ═══ DEUX INVARIANTS, ET LE SECOND EST LE PLUS FACILE À PERDRE ═══
--
-- LE JOURNAL EST EN AJOUT SEUL. Une trace qu'on peut réécrire ne prouve rien,
-- et c'est le premier réflexe de qui vient d'y laisser quelque chose.
--
-- LE JOURNAL NE CONTIENT PAS DE SECRET. `audit.record` recopie les colonnes
-- déclarées dans `audit.auditable_column` ET SEULEMENT CELLES-LÀ ; les autres
-- deviennent `{"redacted": true}`. Sans cette liste, journaliser une paire de
-- jetons écrirait `jti_bearer` en clair — et le journal, qu'on garde des mois
-- et qu'on exporte pour analyse, deviendrait un magasin d'identifiants
-- réutilisables.
--
-- La rédaction est FERMÉE PAR DÉFAUT : une colonne ajoutée demain et absente du
-- registre est masquée, pas exposée. Une assertion ci-dessous le vérifie sur la
-- colonne qui coûterait le plus cher.
--
-- ═══ CE QUE `level` CHANGE ═══
--
--   all     toute écriture produit un événement
--   facts   un UPDATE qui ne touche aucune colonne auditable n'en produit
--           AUCUN — la rotation d'une paire de jetons ne remplit pas le journal
--           de bruit à chaque appel
--
-- Les deux niveaux sont éprouvés, parce que « facts » est une décision qu'un
-- refactoring peut annuler sans que rien ne rougisse.
--
-- ═══ LE MONTAGE ═══
--
-- Un administrateur, une session, et de quoi écrire dans trois tables
-- surveillées différemment. Tout tourne dans la transaction que le lanceur
-- annule — les événements produits ici n'y survivent pas.

SET search_path TO pgtap, public;

SELECT plan(18);

-- ─────────────────────────────────────────────────────────────────────────
--  LE MONTAGE
-- ─────────────────────────────────────────────────────────────────────────

DO $$
DECLARE
    u uuid := gen_random_uuid();
    t uuid := gen_random_uuid();
BEGIN
    -- L'ACTEUR VIENT D'UN RÉGLAGE DE SESSION, posé par le service depuis le
    -- jeton qu'il vient de valider. Absent, la colonne reste nulle : le journal
    -- préfère ne rien dire à inventer un nom.
    PERFORM set_config('app.caller', 'banc-du-journal', false);

    INSERT INTO admin."user" (id) VALUES (u);

    INSERT INTO admin.session (id, user_id, absolute_expires_at)
    VALUES ('eeee1111-1111-4111-8111-111111111111', u, now() + interval '1 hour');

    PERFORM set_config('essai.u', u::text, false);
    PERFORM set_config('essai.t', t::text, false);
END $$;

SELECT is(
    (SELECT count(*)::int FROM audit.event
      WHERE table_name = 'session'
        AND row_key ->> 'id' = 'eeee1111-1111-4111-8111-111111111111'),
    1,
    'opening a session writes exactly one event'
);

SELECT is(
    (SELECT op FROM audit.event
      WHERE table_name = 'session'
        AND row_key ->> 'id' = 'eeee1111-1111-4111-8111-111111111111'),
    'INSERT',
    'and it says which operation it was'
);

-- L'ACTEUR, POSÉ PAR L'APPELANT. Sans lui, « qui a fait ça » ne se répond que
-- par le compte de connexion, qui est le même pour tout le monde.
SELECT is(
    (SELECT actor FROM audit.event
      WHERE table_name = 'session'
        AND row_key ->> 'id' = 'eeee1111-1111-4111-8111-111111111111'),
    'banc-du-journal',
    'and who did it'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  CE QUE LE JOURNAL N'A PAS LE DROIT DE CONTENIR
--
--  LA PLUS IMPORTANTE DU FICHIER. `jti_bearer` et `jti_refresh` ne figurent
--  PAS dans `audit.auditable_column` : ce sont des identifiants de jetons
--  vivants, et un journal qui les recopierait en clair pourrait servir à
--  rejouer ce qu'il documente.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  INSERT INTO admin.token_pair
      (id, session_id, jti_bearer, jti_refresh, inactivity_expires_at)
  VALUES ('ffff1111-1111-4111-8111-111111111111',
          'eeee1111-1111-4111-8111-111111111111',
          'abcdabcd-abcd-4bcd-8bcd-abcdabcdabcd',
          'dcbadcba-dcba-4cba-8cba-dcbadcbadcba',
          now() + interval '15 minutes');
END $$;

SELECT is(
    (SELECT changed -> 'jti_bearer' FROM audit.event
      WHERE table_name = 'token_pair'
        AND row_key ->> 'id' = 'ffff1111-1111-4111-8111-111111111111'),
    '{"redacted": true}'::jsonb,
    'a column outside the audit registry is recorded as redacted'
);

-- ET SA VALEUR N'APPARAÎT NULLE PART. Vérifier la clé `redacted` ne suffit pas :
-- une écriture maladroite pourrait la poser ET recopier la valeur ailleurs dans
-- le même document.
SELECT is(
    (SELECT changed::text LIKE '%abcdabcd-abcd-4bcd-8bcd-abcdabcdabcd%'
       FROM audit.event
      WHERE table_name = 'token_pair'
        AND row_key ->> 'id' = 'ffff1111-1111-4111-8111-111111111111'),
    false,
    'and its value appears nowhere in the recorded document'
);

-- CE QUI EST DÉCLARÉ, LUI, EST EN CLAIR — sinon le journal serait illisible et
-- personne ne s'en servirait.
SELECT is(
    (SELECT changed -> 'session_id' ->> 'after' FROM audit.event
      WHERE table_name = 'token_pair'
        AND row_key ->> 'id' = 'ffff1111-1111-4111-8111-111111111111'),
    'eeee1111-1111-4111-8111-111111111111',
    'while a declared column is recorded in clear'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UN UPDATE NE JOURNALISE QUE CE QUI A CHANGÉ
--
--  Recopier les trente colonnes à chaque écriture rendrait le journal illisible
--  et coûteux, et noierait le champ qui compte.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  UPDATE admin.session SET ended_at = now(), end_reason = 'LOGOUT'
   WHERE id = 'eeee1111-1111-4111-8111-111111111111';
END $$;

SELECT is(
    (SELECT count(*)::int FROM jsonb_object_keys(
        (SELECT changed FROM audit.event
          WHERE table_name = 'session' AND op = 'UPDATE'
            AND row_key ->> 'id' = 'eeee1111-1111-4111-8111-111111111111'))),
    2,
    'an update records the two columns that moved, and no others'
);

-- LE DOCUMENT ENTIER, ET NON SEULEMENT « avant vaut nul ». Comparer un champ
-- absent à NULL passerait aussi bien quand la colonne ne figure PAS du tout —
-- l'assertion serait vraie sans rien affirmer.
SELECT is(
    (SELECT changed -> 'end_reason' FROM audit.event
      WHERE table_name = 'session' AND op = 'UPDATE'
        AND row_key ->> 'id' = 'eeee1111-1111-4111-8111-111111111111'),
    '{"after": "LOGOUT", "before": null}'::jsonb,
    'keeping what the value was before, not only what it became'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE NIVEAU « facts » : LE SILENCE EST UNE DÉCISION
--
--  `token_pair` tourne à chaque appel. Journaliser une rotation qui ne change
--  qu'un `replaced_at` non déclaré remplirait le journal de bruit — et le bruit
--  est ce qui fait qu'on cesse de lire un journal.
-- ═══════════════════════════════════════════════════════════════════════════

-- ON MODIFIE UNE COLONNE NON DÉCLARÉE, ET RIEN NE DOIT S'ÉCRIRE. Lire le
-- niveau dans `audit.watched` ne prouverait que le contenu d'une table ; c'est
-- le SILENCE qu'il faut constater.
DO $$ BEGIN
  UPDATE admin.token_pair
     SET jti_bearer = '0badcafe-0bad-4afe-8afe-0badcafe0bad'
   WHERE id = 'ffff1111-1111-4111-8111-111111111111';
END $$;

SELECT is(
    (SELECT count(*)::int FROM audit.event
      WHERE table_name = 'token_pair' AND op = 'UPDATE'
        AND row_key ->> 'id' = 'ffff1111-1111-4111-8111-111111111111'),
    0,
    'at the facts level, moving only an undeclared column writes nothing'
);

-- ET LE NIVEAU `all` FAIT L'INVERSE sur la même forme d'écriture : la session,
-- surveillée intégralement, a bien journalisé son UPDATE plus haut. Les deux
-- moitiés comptent — sans la seconde, « rien ne s'écrit jamais » passerait.
SELECT is(
    (SELECT count(*)::int FROM audit.event
      WHERE table_name = 'session' AND op = 'UPDATE'
        AND row_key ->> 'id' = 'eeee1111-1111-4111-8111-111111111111'),
    1,
    'while a fully watched table records the very same kind of update'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UNE TABLE QU'ON CESSE DE SURVEILLER CESSE D'ÉCRIRE
--
--  Le registre est une TABLE, pas une liste en dur : retirer une surveillance
--  doit suffire, sans toucher au moindre déclencheur.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  UPDATE audit.watched SET removed_at = now()
   WHERE schema_name = 'webauthn' AND table_name = 'challenge';

  INSERT INTO webauthn.challenge
      (id, user_id, session_id, challenge, action, expires_at, scope,
       target_tenant_id)
  VALUES ('eeee2222-2222-4222-8222-222222222222',
          current_setting('essai.u')::uuid,
          'eeee1111-1111-4111-8111-111111111111',
          '\xaaaa'::bytea, 'tenant.impersonate',
          now() + interval '5 minutes', 'TENANT',
          current_setting('essai.t')::uuid);
END $$;

SELECT is(
    (SELECT count(*)::int FROM audit.event
      WHERE table_name = 'challenge'
        AND row_key ->> 'id' = 'eeee2222-2222-4222-8222-222222222222'),
    0,
    'a table whose watch was withdrawn writes nothing more'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE CLIENT VIENT DE LA LIGNE
--
--  Et non d'un réglage de session que personne ne pose. Deux noms de colonne,
--  deux sens : `tenant_id` quand la ligne APPARTIENT au client,
--  `target_tenant_id` quand elle le VISE.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  UPDATE audit.watched SET removed_at = NULL
   WHERE schema_name = 'webauthn' AND table_name = 'challenge';

  INSERT INTO webauthn.challenge
      (id, user_id, session_id, challenge, action, expires_at, scope,
       target_tenant_id)
  VALUES ('eeee3333-3333-4333-8333-333333333333',
          current_setting('essai.u')::uuid,
          'eeee1111-1111-4111-8111-111111111111',
          '\xbbbb'::bytea, 'tenant.impersonate',
          now() + interval '5 minutes', 'TENANT',
          current_setting('essai.t')::uuid);
END $$;

SELECT is(
    (SELECT tenant_id FROM audit.event
      WHERE table_name = 'challenge'
        AND row_key ->> 'id' = 'eeee3333-3333-4333-8333-333333333333'),
    current_setting('essai.t')::uuid,
    'the tenant is read from the row, under either of its two column names'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UNE TRANSACTION, UN IDENTIFIANT
--
--  Sans lui, une opération qui touche cinq tables devient cinq événements sans
--  lien apparent — et reconstituer un geste devient un travail de datation.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT is(
    (SELECT count(DISTINCT txid)::int FROM audit.event
      WHERE table_name IN ('session', 'token_pair', 'challenge')
        AND row_key ->> 'id' IN (
            'eeee1111-1111-4111-8111-111111111111',
            'ffff1111-1111-4111-8111-111111111111',
            'eeee3333-3333-4333-8333-333333333333')),
    1,
    'every event of one transaction carries the same transaction identifier'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE JOURNAL EST UN CONSTAT
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$UPDATE audit.event SET actor = 'quelqu-un-d-autre'
       WHERE table_name = 'session'$$,
    'XA001', NULL,
    'an event is never rewritten'
);

SELECT throws_ok(
    $$DELETE FROM audit.event WHERE table_name = 'session'$$,
    'XA001', NULL,
    'nor deleted — that is the whole point of keeping it'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA FORME D'UN ÉVÉNEMENT
--
--  Ces deux contraintes ne mordent que sur une écriture DIRECTE — une reprise
--  de données, un correctif. `audit.record` produit toujours des lignes
--  conformes ; c'est justement pourquoi rien ne les éprouverait sans ce banc.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$INSERT INTO audit.event (schema_name, table_name, op, row_key)
      VALUES ('admin', 'session', 'MODIFIE', '{"id": "x"}'::jsonb)$$,
    '23514', NULL,
    'an operation outside the four the log knows is refused'
);

-- LA CLÉ EST PRÉSENTE, SAUF POUR UN TRUNCATE — qui ne vise aucune ligne en
-- particulier. La contrainte dit les DEUX moitiés, et n'en tester qu'une
-- laisserait passer un TRUNCATE qui prétendrait viser une ligne.
SELECT throws_ok(
    $$INSERT INTO audit.event (schema_name, table_name, op)
      VALUES ('admin', 'session', 'DELETE')$$,
    '23514', NULL,
    'an event that is not a truncate names the row it concerns'
);

SELECT throws_ok(
    $$INSERT INTO audit.event (schema_name, table_name, op, row_key)
      VALUES ('admin', 'session', 'TRUNCATE', '{"id": "x"}'::jsonb)$$,
    '23514', NULL,
    'and a truncate names none, because it concerns them all'
);

SELECT * FROM finish();
