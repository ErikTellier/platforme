-- CE QU'UNE COMMANDE SIGNÉE REFUSE.
--
-- ═══ EN QUOI CE BANC DIFFÈRE DE `doctrine.sql` ═══
--
-- `doctrine.sql` lit le CATALOGUE : il dit que la contrainte est là. Il ne dit
-- pas qu'elle mord. Un `CHECK` mal écrit — une comparaison inversée, un `OR`
-- pour un `AND` — y figure exactement comme un bon.
--
-- Ici on écrit la ligne interdite et on exige le refus, avec SON code. C'est la
-- seule vérification qui distingue une contrainte qui protège d'une contrainte
-- qui décore, et la seule que `pnpm mutation:sql` sait lire : il retire chaque
-- objet à son tour et demande à ce banc de rougir.
--
-- ═══ LE CODE ATTENDU EST CELUI QUE L'APPELANT REÇOIT ═══
--
-- Plusieurs gardes se superposent, et le PREMIER qui parle donne son code. Une
-- clé étrangère répond `AD082` avant que la clé étrangère composite n'ait son
-- mot à dire ; un lot inexistant répond `AD111` avant le `CHECK` sur la preuve
-- unique. Ces bancs affirment le code réellement rendu, et non celui de la
-- contrainte qu'on croyait viser : c'est celui-là que le code applicatif devra
-- traiter.
--
-- ═══ TROIS CONTRAINTES SONT INATTEIGNABLES PAR CE CHEMIN, ET C'EST VOULU ═══
--
--   signed_command_scope
--   signed_command_target_matches_scope
--   signed_command_action_fk
--
-- Une commande doit correspondre à son défi (`AD080`), et le défi porte DÉJÀ
-- les mêmes gardes : `challenge_scope`, `challenge_target_matches_scope`,
-- `challenge_action_fk`. Fabriquer une commande hors vocabulaire suppose donc
-- un défi hors vocabulaire, que la table des défis refuse la première.
--
-- Ce sont des filets, atteignables seulement par une écriture directe — une
-- reprise de données, un correctif SQL. Ils apparaîtront comme « SURVIT » au
-- rapport du mutant ; c'est exact, et voici pourquoi.
--
-- ═══ CE QUE CE BANC TUE, MESURÉ ═══
--
-- `pnpm mutation:sql admin` retire chaque objet du schéma à son tour et
-- redemande le banc. SEPT objets meurent, tous sur `signed_command` :
--
--   contrainte    signed_command_digest_length
--   contrainte    uq_command_digest
--   index         uq_command_challenge
--   déclencheur   aaa_signed_command_belongs_to_its_batch
--   déclencheur   signed_command_matches_presence
--   déclencheur   signed_command_no_delete
--   déclencheur   signed_command_no_update
--
-- Sept, plus les trois contraintes ombragées ci-dessus qui survivent — et le
-- fichier dit pourquoi. Le compte de la base entière, famille par famille, vit
-- dans l'en-tête de `packages/harnais/mutation-sql.mjs` : le tenir à deux
-- endroits, c'est le laisser pourrir à l'un des deux.

-- ═══ LE MONTAGE ═══
--
-- Il réutilise l'administrateur d'amorçage. Poser une autorité de plateforme
-- demande une commande signée, qui demande une autorité — l'œuf et la poule que
-- `the_first_authority_is_declared` a déjà tranchés. Tout tourne dans une
-- transaction que le lanceur annule.

SET search_path TO pgtap, public;

SELECT plan(14);

-- `PERFORM` et non `SELECT` : un `SELECT` rendrait sa valeur, qui atterrirait
-- dans le flux TAP entre deux assertions.
DO $$ BEGIN
  PERFORM set_config('essai.admin',
    (SELECT user_id::text FROM admin.platform_admin WHERE revoked_at IS NULL LIMIT 1),
    false);
END $$;

-- Sans administrateur d'amorçage, tout ce qui suit échouerait pour une raison
-- étrangère aux invariants testés. On le dit ici, une fois.
SELECT isnt(
    nullif(current_setting('essai.admin', true), ''),
    NULL,
    'the bootstrap admin exists — every case below depends on it'
);

INSERT INTO admin.session (id, user_id, absolute_expires_at)
VALUES ('22222222-2222-4222-8222-222222222222',
        current_setting('essai.admin')::uuid, now() + interval '1 hour');

INSERT INTO akeys.key (id, kid, user_id, session_id, public_jwk, kms_ref,
                       activated_at, signs_until, published_until, purpose, state)
VALUES ('33333333-3333-4333-8333-333333333333', gen_random_uuid(),
        current_setting('essai.admin')::uuid, '22222222-2222-4222-8222-222222222222',
        '{"kty":"EC"}'::jsonb, 'kms://banc',
        now(), now() + interval '1 hour', now() + interval '2 hours', 'COMMAND', 'ACTIVE');

-- TROIS DÉFIS, ET PAS UN SEUL. `uq_command_challenge` impose un défi pour une
-- commande : celui qui sert la commande valide ne peut pas resservir.
--   ...aaaa  consommé, sert la commande valide
--   ...bbbb  consommé, sert les cas refusés — un refus ne le consomme pas
--   ...cccc  POSÉ mais jamais prouvé
INSERT INTO webauthn.challenge (id, user_id, session_id, challenge, action,
                                expires_at, scope, consumed_at)
VALUES
  ('55555555-5555-4555-8555-5555aaaaaaaa', current_setting('essai.admin')::uuid,
   '22222222-2222-4222-8222-222222222222', '\x0a0a0a0a'::bytea, 'authority.request',
   now() + interval '5 minutes', 'PLATFORM', now()),
  ('55555555-5555-4555-8555-5555bbbbbbbb', current_setting('essai.admin')::uuid,
   '22222222-2222-4222-8222-222222222222', '\x0b0b0b0b'::bytea, 'authority.request',
   now() + interval '5 minutes', 'PLATFORM', now());

INSERT INTO webauthn.challenge (id, user_id, session_id, challenge, action,
                                expires_at, scope)
VALUES ('55555555-5555-4555-8555-5555cccccccc', current_setting('essai.admin')::uuid,
        '22222222-2222-4222-8222-222222222222', '\x0c0c0c0c'::bytea, 'authority.request',
        now() + interval '5 minutes', 'PLATFORM');

-- ═══════════════════════════════════════════════════════════════════════════
--  LE CAS QUI DOIT PASSER
--
--  SANS LUI, TOUT LE RESTE EST SANS VALEUR. Un banc qui n'affirme que des refus
--  passe au vert quand la table refuse TOUT — un montage cassé, et les treize
--  autres se félicitent en chœur.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO admin.signed_command
        (id, user_id, session_id, key_id, challenge_id, action, scope, command_digest, issued_at)
      VALUES (gen_random_uuid(), current_setting('essai.admin')::uuid,
              '22222222-2222-4222-8222-222222222222',
              '33333333-3333-4333-8333-333333333333',
              '55555555-5555-4555-8555-5555aaaaaaaa',
              'authority.request', 'PLATFORM', decode(repeat('61', 32), 'hex'), now())$$,
    'a well-formed command is accepted'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA FORME
-- ═══════════════════════════════════════════════════════════════════════════

-- L'empreinte fait TRENTE-DEUX octets. Plus courte, ce n'est pas un SHA-256 :
-- c'est une valeur qu'on peut fabriquer.
SELECT throws_ok(
    $$INSERT INTO admin.signed_command
        (id, user_id, session_id, key_id, challenge_id, action, scope, command_digest, issued_at)
      VALUES (gen_random_uuid(), current_setting('essai.admin')::uuid,
              '22222222-2222-4222-8222-222222222222',
              '33333333-3333-4333-8333-333333333333',
              '55555555-5555-4555-8555-5555bbbbbbbb',
              'authority.request', 'PLATFORM', decode('6162', 'hex'), now())$$,
    '23514', NULL,
    'a digest shorter than 32 bytes is refused'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  L'UNICITÉ : DEUX PORTES CONTRE LE REJEU
-- ═══════════════════════════════════════════════════════════════════════════

-- La même empreinte deux fois, c'est la même signature présentée deux fois. Le
-- refus vient du MOTEUR, pas d'une vérification applicative qui aurait sa
-- fenêtre de course.
SELECT throws_ok(
    $$INSERT INTO admin.signed_command
        (id, user_id, session_id, key_id, challenge_id, action, scope, command_digest, issued_at)
      VALUES (gen_random_uuid(), current_setting('essai.admin')::uuid,
              '22222222-2222-4222-8222-222222222222',
              '33333333-3333-4333-8333-333333333333',
              '55555555-5555-4555-8555-5555bbbbbbbb',
              'authority.request', 'PLATFORM', decode(repeat('61', 32), 'hex'), now())$$,
    '23505', NULL,
    'replaying a digest already recorded is refused'
);

-- Et un défi ne sert qu'une fois, même pour une empreinte neuve. Sans cette
-- seconde porte, une touche matérielle justifierait deux commandes.
SELECT throws_ok(
    $$INSERT INTO admin.signed_command
        (id, user_id, session_id, key_id, challenge_id, action, scope, command_digest, issued_at)
      VALUES (gen_random_uuid(), current_setting('essai.admin')::uuid,
              '22222222-2222-4222-8222-222222222222',
              '33333333-3333-4333-8333-333333333333',
              '55555555-5555-4555-8555-5555aaaaaaaa',
              'authority.request', 'PLATFORM', decode(repeat('62', 32), 'hex'), now())$$,
    '23505', NULL,
    'one challenge signs one command, never two'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA PORTE DE PRÉSENCE
--
--  Un défi POSÉ n'est pas un défi PROUVÉ. Sans elle, signer reviendrait à
--  demander un défi puis à l'ignorer : la touche matérielle deviendrait
--  facultative, et la non-répudiation une formule.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$INSERT INTO admin.signed_command
        (id, user_id, session_id, key_id, challenge_id, action, scope, command_digest, issued_at)
      VALUES (gen_random_uuid(), current_setting('essai.admin')::uuid,
              '22222222-2222-4222-8222-222222222222',
              '33333333-3333-4333-8333-333333333333',
              '55555555-5555-4555-8555-5555cccccccc',
              'authority.request', 'PLATFORM', decode(repeat('63', 32), 'hex'), now())$$,
    'AD081', NULL,
    'a challenge that was never consumed proves nothing'
);

-- Une commande sans preuve du tout : la porte lit un défi absent.
SELECT throws_ok(
    $$INSERT INTO admin.signed_command
        (id, user_id, session_id, key_id, action, scope, command_digest, issued_at)
      VALUES (gen_random_uuid(), current_setting('essai.admin')::uuid,
              '22222222-2222-4222-8222-222222222222',
              '33333333-3333-4333-8333-333333333333',
              'authority.request', 'PLATFORM', decode(repeat('64', 32), 'hex'), now())$$,
    'AD081', NULL,
    'a command carrying no proof at all is refused'
);

-- LA PRÉSENCE PROUVÉE VAUT POUR UN GESTE PRÉCIS. Prouver sa présence pour une
-- demande n'autorise pas à signer une approbation : c'est ce qui empêche de
-- récolter une touche pour un geste anodin et de la dépenser pour un autre.
SELECT throws_ok(
    $$INSERT INTO admin.signed_command
        (id, user_id, session_id, key_id, challenge_id, action, scope, command_digest, issued_at)
      VALUES (gen_random_uuid(), current_setting('essai.admin')::uuid,
              '22222222-2222-4222-8222-222222222222',
              '33333333-3333-4333-8333-333333333333',
              '55555555-5555-4555-8555-5555bbbbbbbb',
              'authority.approve', 'PLATFORM', decode(repeat('65', 32), 'hex'), now())$$,
    'AD080', NULL,
    'presence proved for one action does not sign another'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  CE QUE LA COMMANDE CITE DOIT LUI APPARTENIR
-- ═══════════════════════════════════════════════════════════════════════════

-- LA CLÉ D'UN AUTRE. Le garde répond avant la clé étrangère composite, et son
-- code est plus précis : la clé ne pouvait pas signer à cet instant.
SELECT throws_ok(
    $$INSERT INTO admin.signed_command
        (id, user_id, session_id, key_id, challenge_id, action, scope, command_digest, issued_at)
      VALUES (gen_random_uuid(), current_setting('essai.admin')::uuid,
              '22222222-2222-4222-8222-222222222222',
              gen_random_uuid(),
              '55555555-5555-4555-8555-5555bbbbbbbb',
              'authority.request', 'PLATFORM', decode(repeat('66', 32), 'hex'), now())$$,
    'AD082', NULL,
    'a key that is not this user''s, in this session, cannot sign'
);

-- LA SESSION D'UN AUTRE. TROIS clés étrangères composites parlent ici d'une
-- seule voix : celle de la session (session_id, user_id), celle du défi
-- (challenge_id, user_id, session_id) et celle de la clé (key_id, user_id,
-- session_id). Chacune porte `session_id` EN PLUS de sa propre cible, et une
-- session inventée les viole donc toutes les trois.
--
-- CONSÉQUENCE POUR LE MUTANT : il n'en tuera aucune. En retirer une laisse les
-- deux autres, le banc reste vert, et le rapport écrit « SURVIT » trois fois.
-- Ce n'est pas un trou de couverture — c'est de la redondance délibérée, la
-- session épinglée trois fois. Aucun banc ne peut distinguer l'indistinguable ;
-- le noter ici vaut mieux que de courir après un vert impossible.
SELECT throws_ok(
    $$INSERT INTO admin.signed_command
        (id, user_id, session_id, key_id, challenge_id, action, scope, command_digest, issued_at)
      VALUES (gen_random_uuid(), current_setting('essai.admin')::uuid,
              gen_random_uuid(),
              '33333333-3333-4333-8333-333333333333',
              '55555555-5555-4555-8555-5555bbbbbbbb',
              'authority.request', 'PLATFORM', decode(repeat('67', 32), 'hex'), now())$$,
    '23503', NULL,
    'a session that is not this user''s is refused'
);

-- UN LOT QUI N'EXISTE PAS. Le garde du lot passe avant le `CHECK` sur la preuve
-- unique : une commande de lot est vérifiée contre son lot, d'abord.
SELECT throws_ok(
    $$INSERT INTO admin.signed_command
        (id, user_id, session_id, key_id, batch_id, batch_seq,
         action, scope, command_digest, issued_at)
      VALUES (gen_random_uuid(), current_setting('essai.admin')::uuid,
              '22222222-2222-4222-8222-222222222222',
              '33333333-3333-4333-8333-333333333333',
              gen_random_uuid(), 1,
              'authority.request', 'PLATFORM', decode(repeat('68', 32), 'hex'), now())$$,
    'AD111', NULL,
    'a command claiming a batch that does not exist is refused'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UNE COMMANDE NE SE RÉÉCRIT NI NE S'EFFACE
--
--  La doctrine « rien ne se supprime », rendue exécutoire. Une preuve qu'on
--  peut modifier après coup n'est pas une preuve ; et effacer une commande
--  compromise détruirait la trace en même temps qu'on la répare — ce qu'un
--  attaquant espère.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$UPDATE admin.signed_command SET action = 'authority.approve'
       WHERE command_digest = decode(repeat('61', 32), 'hex')$$,
    'AD083', NULL,
    'an issued command cannot be rewritten'
);

SELECT throws_ok(
    $$DELETE FROM admin.signed_command
       WHERE command_digest = decode(repeat('61', 32), 'hex')$$,
    'AD083', NULL,
    'an issued command cannot be deleted'
);

-- Et la ligne est toujours là après les deux tentatives.
SELECT is(
    (SELECT count(*)::int FROM admin.signed_command
      WHERE command_digest = decode(repeat('61', 32), 'hex')),
    1,
    'the command is still there, unchanged, after both attempts'
);

SELECT * FROM finish();
