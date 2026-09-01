-- LES VOCABULAIRES, ET CE QUE « DÉPRÉCIER » VEUT DIRE.
--
-- ═══ POURQUOI DES TABLES, ET NON DES ÉNUMÉRATIONS ═══
--
-- Les verbes, les portées, les fournisseurs d'identité, les motifs de fin de
-- session : tout cela vit dans des TABLES. Une énumération PostgreSQL se
-- modifie par une migration et ne porte ni description, ni date de retrait, ni
-- règle associée. Une table, si — et c'est ce qui permet de retirer un mot du
-- vocabulaire sans réécrire l'historique qui l'employait.
--
-- ═══ DÉPRÉCIER N'EST PAS SUPPRIMER ═══
--
-- `code_not_deprecated` refuse un code retiré POUR UNE NOUVELLE VALEUR, et
-- seulement là. Une ligne qui portait déjà ce code continue de vivre, et une
-- écriture qui n'y touche pas passe.
--
-- C'est la moitié qu'on oublie en écrivant ce genre de garde : la déprécation
-- retire un mot du vocabulaire, elle ne gèle pas les lignes qui s'en servaient.
-- Deux assertions ci-dessous tiennent les deux moitiés, parce qu'une seule
-- laisserait passer un durcissement qui casserait la relecture de
-- l'historique.
--
-- ═══ ET DES RÈGLES QUI SE TIENNENT ENTRE ELLES ═══
--
-- `authority_scope` ne porte pas quatre réglages indépendants : ils se
-- contraignent mutuellement. Un bris de glace n'a de sens que là où un second
-- approbateur est exigé — sinon il ne contourne rien. Et une usurpation ne peut
-- pas durer plus longtemps que l'autorité qui l'autorise.
--
-- Ces deux règles-là sont exactement le genre qu'un « petit ajustement de
-- configuration » casse un lundi matin.

SET search_path TO pgtap, public;

SELECT plan(19);

SELECT is(
    (SELECT count(*)::int FROM admin.authority_scope),
    2,
    'the two authority scopes are declared'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA FORME D'UN VERBE
-- ═══════════════════════════════════════════════════════════════════════════

-- `domaine.geste`, en minuscules. Sans forme imposée, « TenantSuspend »,
-- « tenant-suspend » et « tenant.suspend » finiraient par coexister, et le
-- vocabulaire cesserait d'en être un.
SELECT throws_ok(
    $$INSERT INTO admin.command_action (code, description, applies_to)
      VALUES ('TenantSuspend', 'mauvaise forme', 'TENANT')$$,
    '23514', NULL,
    'a verb that does not read as domain.act is refused'
);

SELECT throws_ok(
    $$INSERT INTO admin.command_action (code, description, applies_to)
      VALUES ('tenant.essai', 'portee inventee', 'GALAXIE')$$,
    '23514', NULL,
    'and one that applies to a scope which does not exist'
);

SELECT throws_ok(
    $$DELETE FROM admin.command_action WHERE code = 'tenant.suspend'$$,
    'AD040', NULL,
    'a verb is never deleted — the commands that used it must stay readable'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  DES RÈGLES QUI SE TIENNENT ENTRE ELLES
-- ═══════════════════════════════════════════════════════════════════════════

-- UN BRIS DE GLACE SANS SECOND APPROBATEUR NE CONTOURNE RIEN. La contrainte dit
-- que l'un n'a de sens qu'avec l'autre — et sans elle, on pourrait déclarer une
-- portée « à bris de glace » qui n'exige déjà personne.
SELECT throws_ok(
    $$INSERT INTO admin.authority_scope
        (scope, description, requires_second_approver, allows_break_glass,
         max_impersonation)
      VALUES ('ESSAI', 'bris de glace sans regle a briser', false, true,
              interval '10 minutes')$$,
    '23514', NULL,
    'break-glass without a second approver breaks through nothing'
);

-- UNE USURPATION PLUS LONGUE QUE L'AUTORITÉ QUI L'AUTORISE. Le plafond
-- d'usurpation vit sous celui de l'autorité, pas à côté.
SELECT throws_ok(
    $$INSERT INTO admin.authority_scope
        (scope, description, max_duration, requires_second_approver,
         allows_break_glass, max_impersonation)
      VALUES ('ESSAI', 'usurpation plus longue que l autorite',
              interval '1 hour', true, false, interval '2 hours')$$,
    '23514', NULL,
    'an impersonation ceiling may not outlast the authority that allows it'
);

SELECT throws_ok(
    $$INSERT INTO admin.authority_scope
        (scope, description, requires_second_approver, allows_break_glass,
         max_impersonation)
      VALUES ('ESSAI', 'usurpation nulle', true, false, interval '0')$$,
    '23514', NULL,
    'nor may it be zero, which would declare a ceiling that forbids everything'
);

SELECT throws_ok(
    $$INSERT INTO admin.authority_scope
        (scope, description, max_duration, requires_second_approver,
         allows_break_glass, max_impersonation)
      VALUES ('ESSAI', 'duree nulle', interval '0', true, false,
              interval '0')$$,
    '23514', NULL,
    'and an authority that lasts no time is not an authority'
);

SELECT throws_ok(
    $$DELETE FROM admin.authority_scope WHERE scope = 'TENANT'$$,
    'AD071', NULL,
    'a scope is never deleted — the grants that lean on it must stay readable'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  DÉPRÉCIER N'EST PAS SUPPRIMER
--
--  LES DEUX MOITIÉS. Un code retiré refuse une NOUVELLE valeur ; les lignes qui
--  le portaient déjà continuent de vivre. Sans la seconde assertion, un
--  durcissement gèlerait tout l'historique et rien ne rougirait.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$
DECLARE
    u uuid := gen_random_uuid();
BEGIN
    INSERT INTO admin."user" (id) VALUES (u);

    INSERT INTO admin.session (id, user_id, absolute_expires_at, ended_at, end_reason)
    VALUES ('0801aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', u,
            now() + interval '1 hour', now(), 'LOGOUT');

    -- On retire le motif APRÈS qu'une ligne l'a employé.
    UPDATE admin.session_end_reason SET deprecated_at = now()
     WHERE code = 'LOGOUT';

    PERFORM set_config('essai.u', u::text, false);
END $$;

SELECT throws_ok(
    $$INSERT INTO admin.session
        (user_id, absolute_expires_at, ended_at, end_reason)
      VALUES (current_setting('essai.u')::uuid, now() + interval '1 hour',
              now(), 'LOGOUT')$$,
    'AD060', NULL,
    'a deprecated code is refused for a new value'
);

-- ET LA LIGNE QUI LE PORTAIT DÉJÀ NE BOUGE PAS. Une écriture qui ne touche pas
-- au code passe, sinon déprécier un motif rendrait illisible tout ce qui s'en
-- servait.
SELECT lives_ok(
    $$UPDATE admin.session SET cnf_jkt = NULL
       WHERE id = '0801aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'$$,
    'while a row that already carried it keeps living untouched'
);

SELECT throws_ok(
    $$DELETE FROM admin.session_end_reason WHERE code = 'LOGOUT'$$,
    'AD040', NULL,
    'and the retired code itself is never deleted'
);

SELECT throws_ok(
    $$DELETE FROM admin.identity_provider WHERE code = 'ENTRA'$$,
    'AD040', NULL,
    'no more than an identity provider is'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LES RÉGLAGES DE PURGE
--
--  Ils décident ce qui disparaît. Une valeur absurde ne se voit pas au moment
--  où on l'écrit — elle se voit six mois plus tard, quand il manque des
--  données ou qu'il n'en manque aucune.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$UPDATE admin.retention SET keep_for = interval '0'
       WHERE relation = (SELECT relation FROM admin.retention LIMIT 1)$$,
    '23514', NULL,
    'a retention that keeps nothing for no time is refused'
);

SELECT throws_ok(
    $$UPDATE admin.retention SET batch_size = 0
       WHERE relation = (SELECT relation FROM admin.retention LIMIT 1)$$,
    '23514', NULL,
    'and a purge batch of zero rows would never finish'
);

SELECT throws_ok(
    $$UPDATE audit.retention SET per_call = 0
       WHERE relation = (SELECT relation FROM audit.retention LIMIT 1)$$,
    '23514', NULL,
    'the same holds for the audit ring'
);

SELECT throws_ok(
    $$DELETE FROM admin.retention
       WHERE relation = (SELECT relation FROM admin.retention LIMIT 1)$$,
    'AD040', NULL,
    'and a retention rule is never deleted, only changed'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE REGISTRE DE CE QUI EST SURVEILLÉ
-- ═══════════════════════════════════════════════════════════════════════════

-- SANS CLÉ, UN ÉVÉNEMENT NE DÉSIGNE AUCUNE LIGNE. Surveiller une table sans
-- dire par quoi l'identifier produirait un journal qu'on ne peut pas relier.
SELECT throws_ok(
    $$INSERT INTO audit.watched (schema_name, table_name, level, key_columns)
      VALUES ('admin', 'spent_proof', 'all', '{}')$$,
    '23514', NULL,
    'watching a table without saying how to name its rows is refused'
);

SELECT throws_ok(
    $$INSERT INTO audit.watched (schema_name, table_name, level, key_columns)
      VALUES ('admin', 'spent_proof', 'parfois', '{id}')$$,
    '23514', NULL,
    'and a level outside the two the recorder knows'
);

SELECT * FROM finish();
