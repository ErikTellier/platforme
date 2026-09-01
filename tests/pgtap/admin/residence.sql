-- SOUS QUELLE JURIDICTION, ET QUI PEUT Y TOUCHER.
--
-- ═══ LA PORTE QUE `may_read` CONSULTE EN PREMIER ═══
--
-- `cloisonnement.sql` a prouvé que la résidence prime sur l'autorité : un
-- administrateur de plateforme ne voit rien d'un client dont il n'a pas la
-- juridiction. Ce fichier prouve l'autre moitié — que la résidence elle-même
-- s'obtient et se perd dans les règles.
--
-- Deux tables, deux natures :
--
--   tenant_residency     où vit un CLIENT. Un fait, pas un réglage.
--   operator_residency   quelles juridictions un OPÉRATEUR peut servir. Une
--                        autorisation, donc révocable.
--
-- ═══ `AD102` : DÉPLACER UN CLIENT N'EST PAS UN `UPDATE` ═══
--
-- `tenant_residency_is_a_fact` refuse TOUTE écriture sur une ligne existante —
-- pas seulement un changement de région, n'importe quelle modification, même
-- réécrire la même valeur. Le message du schéma le dit mieux que je ne le
-- ferais : « déplacer un client d'une juridiction à une autre est un export,
-- un consentement, parfois une notification à une autorité de contrôle. C'est
-- un projet, pas un UPDATE. »
--
-- Une assertion ci-dessous écrit la MÊME valeur pour le vérifier : la garde
-- n'est pas « la région ne change pas », elle est « on ne touche pas ».
--
-- ═══ ET UNE ASYMÉTRIE À NE PAS MANQUER ═══
--
-- L'opérateur, lui, se révoque. `operator_residency_live_uq` porte sur le
-- COUPLE (opérateur, région) : le même opérateur peut servir deux juridictions
-- à la fois, ce qui est le cas normal d'une astreinte. Un index sur le seul
-- opérateur aurait paru raisonnable et aurait interdit ça — une assertion le
-- tient en place.
--
-- ═══ LE MONTAGE ═══
--
--   C   l'administrateur d'amorçage, qui accorde et révoque
--   O   un opérateur, accrédité puis coupé
--   T   un client, domicilié une fois pour toutes

SET search_path TO pgtap, public;

SELECT plan(21);

-- ─────────────────────────────────────────────────────────────────────────
--  LE MONTAGE
-- ─────────────────────────────────────────────────────────────────────────

CREATE FUNCTION pg_temp.commande(
    p_user uuid, p_session uuid, p_key uuid, p_action text, p_graine text,
    p_scope text DEFAULT 'PLATFORM', p_tenant uuid DEFAULT NULL
) RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE
    v_defi uuid := gen_random_uuid();
    v_cmd  uuid := gen_random_uuid();
BEGIN
    INSERT INTO webauthn.challenge
        (id, user_id, session_id, challenge, action, expires_at, scope,
         target_tenant_id, consumed_at)
    VALUES (v_defi, p_user, p_session, decode(repeat(p_graine, 4), 'hex'),
            p_action, now() + interval '5 minutes', p_scope, p_tenant, now());

    INSERT INTO admin.signed_command
        (id, user_id, session_id, key_id, challenge_id, action, scope,
         target_tenant_id, command_digest, issued_at)
    VALUES (v_cmd, p_user, p_session, p_key, v_defi, p_action, p_scope,
            p_tenant, decode(repeat(p_graine, 32), 'hex'), now());

    RETURN v_cmd;
END;
$f$;

DO $$
DECLARE
    c  uuid := (SELECT user_id FROM admin.platform_admin WHERE revoked_at IS NULL LIMIT 1);
    o  uuid := gen_random_uuid();
    t  uuid := gen_random_uuid();
    sc uuid := gen_random_uuid();
    kc uuid := gen_random_uuid();
BEGIN
    PERFORM set_config('app.caller', 'banc-de-residence', false);
    INSERT INTO admin."user" (id) VALUES (o);

    INSERT INTO admin.session (id, user_id, absolute_expires_at)
    VALUES (sc, c, now() + interval '1 hour');

    INSERT INTO akeys.key
        (id, kid, user_id, session_id, public_jwk, kms_ref,
         activated_at, signs_until, published_until, purpose, state)
    VALUES (kc, gen_random_uuid(), c, sc, '{"kty":"EC"}'::jsonb, 'kms://banc',
            now(), now() + interval '1 hour', now() + interval '2 hours',
            'COMMAND', 'ACTIVE');

    INSERT INTO admin.residency_region (code, description, jurisdiction)
    VALUES ('EU_WEST', 'Europe de l ouest', 'RGPD'),
           ('US_EAST', 'Cote est des Etats-Unis', 'CLOUD Act')
    ON CONFLICT (code) DO NOTHING;

    PERFORM set_config('essai.c', c::text, false);
    PERFORM set_config('essai.o', o::text, false);
    PERFORM set_config('essai.t', t::text, false);

    -- Une commande par écriture : rien ne les consomme, mais chacune doit être
    -- de la bonne action et du bon périmètre.
    FOR i IN 1..9 LOOP
        PERFORM set_config(
            'essai.g' || i,
            pg_temp.commande(c, sc, kc, 'residency.grant',
                             lpad(to_hex(96 + i), 2, '0'))::text, false);
    END LOOP;

    PERFORM set_config('essai.v1',
        pg_temp.commande(c, sc, kc, 'residency.revoke', '70')::text, false);
    PERFORM set_config('essai.v2',
        pg_temp.commande(c, sc, kc, 'residency.revoke', '71')::text, false);
    PERFORM set_config('essai.d1',
        pg_temp.commande(c, sc, kc, 'residency.declare', '72', 'TENANT', t)::text, false);
    PERFORM set_config('essai.d2',
        pg_temp.commande(c, sc, kc, 'residency.declare', '73', 'TENANT', t)::text, false);
END $$;

SELECT isnt(
    nullif(current_setting('essai.o', true), ''),
    NULL,
    'the operator and the two jurisdictions of this bench exist'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  ACCRÉDITER UN OPÉRATEUR
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO admin.operator_residency
        (id, user_id, region_code, reason, granted_by, command_id)
      VALUES ('dada1111-1111-4111-8111-111111111111',
              current_setting('essai.o')::uuid, 'EU_WEST',
              'Astreinte europeenne', current_setting('essai.c')::uuid,
              current_setting('essai.g1')::uuid)$$,
    'an operator is accredited for a jurisdiction'
);

-- DEUX JURIDICTIONS À LA FOIS, ET C'EST LE CAS NORMAL. L'unicité porte sur le
-- COUPLE opérateur-région : une astreinte couvre souvent plusieurs zones. Un
-- index sur le seul opérateur aurait paru raisonnable et interdirait ça.
SELECT lives_ok(
    $$INSERT INTO admin.operator_residency
        (user_id, region_code, reason, granted_by, command_id)
      VALUES (current_setting('essai.o')::uuid, 'US_EAST',
              'Astreinte americaine', current_setting('essai.c')::uuid,
              current_setting('essai.g2')::uuid)$$,
    'and may hold a second one at the same time'
);

-- MAIS PAS DEUX FOIS LA MÊME. Deux lignes vivantes pour un même couple
-- donneraient deux révocations à faire, et on en oublierait une.
SELECT throws_ok(
    $$INSERT INTO admin.operator_residency
        (user_id, region_code, reason, granted_by, command_id)
      VALUES (current_setting('essai.o')::uuid, 'EU_WEST',
              'Doublon', current_setting('essai.c')::uuid,
              current_setting('essai.g3')::uuid)$$,
    '23505', NULL,
    'never twice the same, which would leave one revocation to forget'
);

-- S'ACCRÉDITER SOI-MÊME. La même règle que « personne ne se donne l'autorité »,
-- appliquée à la géographie : sans elle, un opérateur s'ouvrirait les
-- juridictions dont il a besoin.
SELECT throws_ok(
    $$INSERT INTO admin.operator_residency
        (user_id, region_code, reason, granted_by, command_id)
      VALUES (current_setting('essai.c')::uuid, 'US_EAST',
              'Pour moi-meme', current_setting('essai.c')::uuid,
              current_setting('essai.g4')::uuid)$$,
    '23514', NULL,
    'nobody grants themselves a jurisdiction'
);

-- UN MOTIF FAIT DE BLANCS N'EST PAS UN MOTIF. « Pourquoi cet opérateur
-- pouvait-il servir cette région » est la question posée en revue.
SELECT throws_ok(
    $$INSERT INTO admin.operator_residency
        (user_id, region_code, reason, granted_by, command_id)
      VALUES (current_setting('essai.o')::uuid, 'US_EAST', '   ',
              current_setting('essai.c')::uuid,
              current_setting('essai.g5')::uuid)$$,
    '23514', NULL,
    'a reason made of spaces is not a reason'
);

-- UNE RÉGION QUI N'EXISTE PAS. Le vocabulaire des juridictions est une table,
-- pas une chaîne libre : « EU-WEST » et « EU_WEST » ne doivent pas coexister.
SELECT throws_ok(
    $$INSERT INTO admin.operator_residency
        (user_id, region_code, reason, granted_by, command_id)
      VALUES (current_setting('essai.o')::uuid, 'ATLANTIDE', 'Astreinte',
              current_setting('essai.c')::uuid,
              current_setting('essai.g6')::uuid)$$,
    '23503', NULL,
    'and the jurisdiction comes from the vocabulary, not from prose'
);

-- SANS COMMANDE SIGNÉE, RIEN. Ouvrir une juridiction est un geste de
-- plateforme : il se prouve par une touche matérielle.
SELECT throws_ok(
    $$INSERT INTO admin.operator_residency
        (user_id, region_code, reason, granted_by, command_id)
      VALUES (current_setting('essai.o')::uuid, 'US_EAST', 'Astreinte',
              current_setting('essai.c')::uuid,
              current_setting('essai.v1')::uuid)$$,
    'AD101', NULL,
    'a grant leaning on a revocation command is refused'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  ET LA JURIDICTION S'OUVRE VRAIMENT
--
--  Sans cette assertion, tout ce qui précède décrirait des lignes, pas un
--  droit. C'est `may_reside` que `may_read` consulte.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  INSERT INTO admin.tenant_residency (tenant_id, region_code, declared_by, command_id)
  VALUES (current_setting('essai.t')::uuid, 'EU_WEST',
          current_setting('essai.c')::uuid, current_setting('essai.d1')::uuid);
END $$;

SELECT ok(
    admin.may_reside(current_setting('essai.o')::uuid,
                     current_setting('essai.t')::uuid),
    'the accredited operator may serve a tenant of that jurisdiction'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  COUPER UNE ACCRÉDITATION
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$UPDATE admin.operator_residency SET revoked_at = now()
       WHERE id = 'dada1111-1111-4111-8111-111111111111'$$,
    '23514', NULL,
    'a revocation without an author is refused here too'
);

-- AVEC UNE COMMANDE VALIDE, sinon `residency_is_signed` répond `AD101` le
-- premier et l'assertion affirmerait autre chose que son intitulé. L'ordre est
-- alphabétique : `revocation_is_signed` avant `revocation_only`.
SELECT throws_ok(
    $$UPDATE admin.operator_residency
         SET revoked_at = now(), revoked_by = current_setting('essai.c')::uuid,
             revoked_command_id = current_setting('essai.v1')::uuid,
             reason = 'motif reecrit'
       WHERE id = 'dada1111-1111-4111-8111-111111111111'$$,
    'AD103', NULL,
    'and the reason it was granted cannot be rewritten while cutting it'
);

SELECT throws_ok(
    $$UPDATE admin.operator_residency
         SET revoked_at = now(), revoked_by = current_setting('essai.c')::uuid,
             revoked_command_id = current_setting('essai.g7')::uuid
       WHERE id = 'dada1111-1111-4111-8111-111111111111'$$,
    'AD101', NULL,
    'nor cut by a command that is not a revocation'
);

SELECT lives_ok(
    $$UPDATE admin.operator_residency
         SET revoked_at = now(), revoked_by = current_setting('essai.c')::uuid,
             revoked_command_id = current_setting('essai.v1')::uuid
       WHERE id = 'dada1111-1111-4111-8111-111111111111'$$,
    'an accreditation is cut by a signed revocation'
);

-- ET LA JURIDICTION SE REFERME. C'est ce que la révocation veut dire.
SELECT ok(
    NOT admin.may_reside(current_setting('essai.o')::uuid,
                         current_setting('essai.t')::uuid),
    'and the operator may no longer serve that jurisdiction'
);

SELECT throws_ok(
    $$UPDATE admin.operator_residency
         SET revoked_at = now(), revoked_by = current_setting('essai.c')::uuid,
             revoked_command_id = current_setting('essai.v2')::uuid
       WHERE id = 'dada1111-1111-4111-8111-111111111111'$$,
    'AD103', NULL,
    'an accreditation already cut is not cut again'
);

SELECT throws_ok(
    $$DELETE FROM admin.operator_residency
       WHERE id = 'dada1111-1111-4111-8111-111111111111'$$,
    'AD040', NULL,
    'and never deleted — it is the trace of what was open'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA RÉSIDENCE D'UN CLIENT EST UN FAIT
--
--  LE CŒUR DU FICHIER. Déplacer un client d'une juridiction à une autre est un
--  export, un consentement, parfois une notification à une autorité de
--  contrôle. C'est un projet, pas un `UPDATE` — et le schéma refuse le geste,
--  pas seulement le résultat.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$UPDATE admin.tenant_residency SET region_code = 'US_EAST'
       WHERE tenant_id = current_setting('essai.t')::uuid$$,
    'AD102', NULL,
    'a tenant is not moved from one jurisdiction to another by an update'
);

-- LA MÊME VALEUR, ET C'EST TOUJOURS REFUSÉ. La garde n'est pas « la région ne
-- change pas », elle est « on ne touche pas à cette ligne » — un déclencheur
-- qui comparerait l'avant et l'après laisserait passer celui-ci, et avec lui
-- toute écriture qui prépare la suivante.
SELECT throws_ok(
    $$UPDATE admin.tenant_residency SET region_code = region_code
       WHERE tenant_id = current_setting('essai.t')::uuid$$,
    'AD102', NULL,
    'and not even by writing back the value it already had'
);

SELECT throws_ok(
    $$DELETE FROM admin.tenant_residency
       WHERE tenant_id = current_setting('essai.t')::uuid$$,
    'AD040', NULL,
    'nor by deleting the declaration and starting over'
);

-- DÉCLARER DEMANDE UNE COMMANDE DE DÉCLARATION, pas n'importe laquelle.
SELECT throws_ok(
    $$INSERT INTO admin.tenant_residency
        (tenant_id, region_code, declared_by, command_id)
      VALUES (gen_random_uuid(), 'US_EAST', current_setting('essai.c')::uuid,
              current_setting('essai.g8')::uuid)$$,
    'AD101', NULL,
    'declaring a residency leans on a declaration command, not any command'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  CE QUE LE JOURNAL EN GARDE
-- ═══════════════════════════════════════════════════════════════════════════

SELECT is(
    (SELECT changed -> 'region_code' ->> 'after' FROM audit.event
      WHERE table_name = 'tenant_residency' AND op = 'INSERT'
      ORDER BY event_id DESC LIMIT 1),
    'EU_WEST',
    'the journal records under which jurisdiction a client was placed'
);

SELECT * FROM finish();
