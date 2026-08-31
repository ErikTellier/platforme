-- Up Migration

-- UN JOURNAL D'AUDIT DANS LA BASE, PAS À CÔTÉ.
--
-- Le contrat de cette base disait jusqu'ici « émettez le flux d'audit vers le
-- SIEM ». C'est une obligation que la base ne peut pas faire respecter, donc
-- ce n'est pas une garantie : c'est un espoir. Et elle rend le schéma
-- inutilisable tel quel pour qui n'a pas de SIEM — c'est-à-dire pour la
-- plupart des applications qui pourraient le réutiliser.
--
-- Ce schéma transforme cette obligation externe en fait interne. Un trigger
-- écrit ce qui s'est produit ; l'application ne peut ni l'omettre ni le forger.
--
-- TROIS CHOSES QU'IL NE FAIT PAS, ET IL FAUT LES SAVOIR AVANT DE S'Y FIER :
--
--   1. Il ne voit aucun SELECT. Un trigger ne se déclenche pas sur une
--      lecture. L'aspiration de données par un appelant légitime reste
--      invisible ici — c'est le même mur que crypto.key_access_log.
--
--   2. Il ne voit aucune action ANNULÉE. La ligne d'audit est annulée avec la
--      transaction qui l'a écrite. On journalise ce qui s'est produit, pas ce
--      qui a été tenté. Les refus sont déjà portés par les SQLSTATE
--      personnalisés vers le journal applicatif, et les auditer ici
--      demanderait une transaction autonome — un mécanisme qui échoue en
--      silence, donc pire que son absence.
--
--   3. Il n'est pas un backup. La preuve vit dans la base qu'elle audite.
--
-- CE QU'IL REFUSE D'ÊTRE : un chemin d'exfiltration. Un trigger générique qui
-- ferait to_jsonb(NEW) recopierait les secrets de cette base dans une table aux privilèges différents — on aurait passé
-- la journée à révoquer SELECT sur ces colonnes pour les republier à côté.
--
-- Donc : LISTE BLANCHE, FERMÉE PAR DÉFAUT. Une colonne est expurgée sauf
-- déclaration explicite. Une colonne ajoutée par une migration future est
-- expurgée sans que personne y pense. Le journal dit toujours QU'ELLE a
-- changé — jamais en quoi.
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers and functions (custom SQLSTATE):
--     XA001  the audit log is a record: never updated, never deleted
--     XA010  a watched table must have a primary key to identify its rows
--     XA011  a column declared auditable does not exist on that table
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

CREATE SCHEMA audit;

COMMENT ON SCHEMA audit IS
'Journal des écritures de cette base, alimenté par déclencheur.

AUTONOME : ce schéma est créé par la migration de cette base et ne dépend
d''aucune autre. Une application sans SIEM obtient malgré tout une piste
d''audit inaltérable.';


-- =====================================================================
--  1. CE QUI EST AUDITÉ — DES DONNÉES, PAS DU DDL
--
--  Déclarer les tables surveillées dans une table plutôt que dans le code
--  du déclencheur permet de changer le périmètre sans migration, et rend
--  le périmètre LISIBLE : une requête répond à « qu'est-ce qui est
--  audité, exactement ? ».
-- =====================================================================

CREATE TABLE audit.watched (
    schema_name  name        NOT NULL,
    table_name   name        NOT NULL,

    -- 'all'   : toute écriture produit un événement.
    -- 'facts' : INSERT et DELETE toujours ; UPDATE seulement si une colonne
    --           DÉCLARÉE change. auth.session_token_history tourne à chaque
    --           refresh — l'auditer intégralement doublerait le chemin
    --           d'écriture le plus chaud de cette base. Ce coût doit être une
    --           décision par table, pas un accident global.
    level        text        NOT NULL DEFAULT 'all',

    -- Figées au moment de la déclaration plutôt que relues à chaque ligne :
    -- interroger le catalogue à chaque écriture coûterait plus cher que
    -- l'écriture elle-même.
    key_columns  name[]      NOT NULL,

    added_at     timestamptz NOT NULL DEFAULT now(),
    removed_at   timestamptz,

    CONSTRAINT watched_pk PRIMARY KEY (schema_name, table_name),
    CONSTRAINT watched_level CHECK (level IN ('all', 'facts')),
    CONSTRAINT watched_has_key CHECK (cardinality(key_columns) > 0)
);

COMMENT ON TABLE audit.watched IS
'Le périmètre de l''audit, en données. removed_at arrête la journalisation
sans supprimer la ligne : on garde trace de ce qui A ÉTÉ audité, sinon un
trou dans le journal devient indiscernable d''une absence d''activité.';

COMMENT ON COLUMN audit.watched.key_columns IS
'Colonnes identifiant la ligne. Une clé déclarée secrète est journalisée
HACHÉE : les lignes restent corrélables entre elles sans exposer la valeur.';


CREATE TABLE audit.auditable_column (
    schema_name  name        NOT NULL,
    table_name   name        NOT NULL,
    column_name  name        NOT NULL,
    declared_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT auditable_column_pk
        PRIMARY KEY (schema_name, table_name, column_name),
    CONSTRAINT auditable_column_watched_fk
        FOREIGN KEY (schema_name, table_name)
        REFERENCES audit.watched (schema_name, table_name) ON DELETE CASCADE
);

COMMENT ON TABLE audit.auditable_column IS
'LA LISTE BLANCHE. Une colonne absente d''ici est expurgée — le journal dit
qu''elle a changé, jamais en quoi.

C''est volontairement l''inverse d''une liste noire : une liste noire oublie
la colonne que la prochaine migration ajoutera, et l''oubli est silencieux.
Ici l''oubli expurge.';


-- =====================================================================
--  2. LE JOURNAL
--
--  Partitionné par mois. La rétention devient « détacher une partition »
--  — un levier pour qui applique une politique, pas une politique gravée
--  dans le schéma. Aucun cron : une partition PAR DÉFAUT reçoit tout ce
--  qui tombe hors des partitions créées, donc rien ne se perd jamais,
--  même si personne n'appelle ensure_partitions().
-- =====================================================================

CREATE TABLE audit.event (
    occurred_at  timestamptz NOT NULL DEFAULT now(),
    event_id     bigint      GENERATED ALWAYS AS IDENTITY,

    -- Ce que le serveur sait, et ce que l'application affirme. Les deux, parce
    -- qu'ils peuvent diverger : c'est précisément la divergence qui est
    -- intéressante quand on relit un journal après un incident.
    db_user      name        NOT NULL DEFAULT session_user,
    actor        text,
    tenant_id    uuid,

    txid         xid8        NOT NULL DEFAULT pg_current_xact_id(),
    schema_name  name        NOT NULL,
    table_name   name        NOT NULL,
    op           text        NOT NULL,

    row_key      jsonb,
    changed      jsonb       NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT event_pk PRIMARY KEY (occurred_at, event_id),
    CONSTRAINT event_op CHECK (op IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')),
    -- Une ligne identifiée pour toute écriture ligne à ligne ; TRUNCATE
    -- n'en a aucune, par nature.
    CONSTRAINT event_row_key_present CHECK (
        (op = 'TRUNCATE' AND row_key IS NULL)
     OR (op <> 'TRUNCATE' AND row_key IS NOT NULL))
) PARTITION BY RANGE (occurred_at);

CREATE TABLE audit.event_overflow PARTITION OF audit.event DEFAULT;

COMMENT ON TABLE audit.event IS
'Ce qui s''est produit dans cette base. Écrit par déclencheur en SECURITY
DEFINER : l''application n''a aucun privilège dessus, elle ne peut donc ni
forger ni omettre une entrée.

NE CONTIENT AUCUN SELECT — un déclencheur ne voit pas une lecture.
NE CONTIENT AUCUNE ACTION ANNULÉE — la ligne meurt avec sa transaction.';

COMMENT ON TABLE audit.event_overflow IS
'Reçoit ce qui tombe hors des partitions mensuelles créées. Sa raison d''être
est qu''un journal ne doit JAMAIS refuser une écriture : sans elle, un mois
non provisionné ferait échouer chaque écriture de la base qu''il audite.
Une ligne ici veut dire « ensure_partitions n''a pas été appelé », pas
« l''événement est perdu ».';

COMMENT ON COLUMN audit.event.changed IS
'{colonne: {before, after}} pour les colonnes déclarées auditables,
{colonne: {redacted: true}} pour les autres. Seules les colonnes AYANT
changé figurent — un UPDATE d''une colonne sur trente en journalise une.';

COMMENT ON COLUMN audit.event.txid IS
'Regroupe les événements d''une même transaction. Sans lui, une opération
qui touche cinq tables devient cinq événements sans lien apparent.';

CREATE INDEX event_by_table
    ON audit.event (schema_name, table_name, occurred_at DESC);
CREATE INDEX event_by_actor
    ON audit.event (actor, occurred_at DESC) WHERE actor IS NOT NULL;
CREATE INDEX event_by_tenant
    ON audit.event (tenant_id, occurred_at DESC) WHERE tenant_id IS NOT NULL;
CREATE INDEX event_by_txid
    ON audit.event (txid);


-- --- Provisionner les partitions ------------------------------------
-- Idempotent, sûr à appeler à chaque démarrage. Ne détruit rien : la
-- rétention est une décision qui n'appartient pas à ce schéma.
CREATE FUNCTION audit.ensure_partitions(p_months int DEFAULT 12)
RETURNS int
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    made  int := 0;
    start date;
    i     int;
BEGIN
    FOR i IN 0 .. p_months LOOP
        start := date_trunc('month', now())::date + (i || ' months')::interval;
        IF NOT EXISTS (
            SELECT FROM pg_catalog.pg_class c
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'audit'
               AND c.relname = 'event_' || to_char(start, 'YYYYMM')
        ) THEN
            EXECUTE format(
                'CREATE TABLE audit.%I PARTITION OF audit.event '
                'FOR VALUES FROM (%L) TO (%L)',
                'event_' || to_char(start, 'YYYYMM'),
                start,
                (start + interval '1 month')::date);
            made := made + 1;
        END IF;
    END LOOP;
    RETURN made;
END;
$$;

COMMENT ON FUNCTION audit.ensure_partitions(int) IS
'Crée les partitions mensuelles manquantes, jusqu''à p_months mois en avant.
Idempotente : renvoie le nombre effectivement créées. Rien ne dépend d''elle
pour fonctionner — la partition par défaut absorbe le reste — mais sans elle
tout finit dans un seul tas et la rétention par détachement devient
impossible.';


-- =====================================================================
--  3. LE DÉCLENCHEUR
-- =====================================================================

CREATE FUNCTION audit.record()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    w          record;
    allowed    name[];
    before_row jsonb;
    after_row  jsonb;
    shape      jsonb;
    changed    jsonb := '{}'::jsonb;
    keys       jsonb := '{}'::jsonb;
    col        text;
    kc         name;
    b          jsonb;
    a          jsonb;
    raw        text;
BEGIN
    SELECT level, key_columns INTO w
      FROM audit.watched
     WHERE schema_name = TG_TABLE_SCHEMA
       AND table_name  = TG_TABLE_NAME
       AND removed_at IS NULL;

    -- La surveillance a été retirée mais le déclencheur est resté. Ne rien
    -- journaliser est exactement ce qui a été demandé.
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT coalesce(array_agg(column_name), '{}'::name[]) INTO allowed
      FROM audit.auditable_column
     WHERE schema_name = TG_TABLE_SCHEMA AND table_name = TG_TABLE_NAME;

    IF TG_OP = 'TRUNCATE' THEN
        INSERT INTO audit.event (actor, tenant_id, schema_name, table_name, op)
        VALUES (nullif(current_setting('app.caller', true), ''),
                -- Cette base est un plan de contrôle : elle n'a pas de tenant,
                -- donc rien à lier. NULL explicite plutôt qu'un réglage inventé
                -- que personne ne poserait jamais.
                NULL,
                TG_TABLE_SCHEMA, TG_TABLE_NAME, 'TRUNCATE');
        RETURN NULL;
    END IF;

    before_row := CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END;
    after_row  := CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END;
    shape      := coalesce(after_row, before_row);

    FOR col IN SELECT jsonb_object_keys(shape) LOOP
        b := before_row -> col;
        a := after_row  -> col;

        -- Seules les colonnes qui ont bougé. Un UPDATE d'une colonne sur
        -- trente doit produire un événement d'une colonne, sinon le journal
        -- pèse plus lourd que la base et personne ne le relit.
        CONTINUE WHEN TG_OP = 'UPDATE' AND b IS NOT DISTINCT FROM a;

        IF col::name = ANY (allowed) THEN
            changed := changed || jsonb_build_object(
                col, jsonb_build_object('before', b, 'after', a));
        ELSE
            changed := changed || jsonb_build_object(
                col, jsonb_build_object('redacted', true));
        END IF;
    END LOOP;

    -- 'facts' : le bruit d'une table qui tourne ne produit un événement que
    -- si un fait DÉCLARÉ a changé.
    IF TG_OP = 'UPDATE' AND w.level = 'facts'
       AND NOT EXISTS (SELECT FROM jsonb_object_keys(changed) k
                        WHERE k::name = ANY (allowed)) THEN
        RETURN NULL;
    END IF;

    FOREACH kc IN ARRAY w.key_columns LOOP
        IF kc = ANY (allowed) THEN
            keys := keys || jsonb_build_object(kc, shape -> kc::text);
        ELSE
            -- Haché, pas omis : deux événements sur la même ligne restent
            -- corrélables sans que la valeur soit exposée.
            raw := shape ->> kc::text;
            -- sha256() est natif : aucune extension, donc rien à installer sur
            -- le serveur qui accueillera cette base. Une dépendance à pgcrypto
            -- ici rendrait le schéma non déployable là où l'extension n'est
            -- pas disponible, ce qui est exactement ce qu'on cherche à éviter.
            keys := keys || jsonb_build_object(kc,
                CASE WHEN raw IS NULL THEN NULL
                     ELSE to_jsonb('sha256:' ||
                          encode(sha256(convert_to(raw, 'UTF8')), 'hex')) END);
        END IF;
    END LOOP;

    INSERT INTO audit.event (
        actor, tenant_id, schema_name, table_name, op, row_key, changed)
    VALUES (
        nullif(current_setting('app.caller', true), ''),
        NULL,   -- pas de tenant dans un plan de contrôle
        TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP, keys, changed);

    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION audit.record() IS
'Journalise une écriture. SECURITY DEFINER parce que les rôles applicatifs
n''ont AUCUN privilège sur audit.event : ils ne peuvent donc ni omettre une
entrée, ni en forger une, ni relire celles des autres.';


-- --- Déclarer une table surveillée ----------------------------------
CREATE FUNCTION audit.watch(
    p_schema  name,
    p_table   name,
    p_columns name[] DEFAULT '{}',
    p_level   text   DEFAULT 'all')
RETURNS void
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    keys    name[];
    missing name;
BEGIN
    SELECT array_agg(a.attname ORDER BY k.ord) INTO keys
      FROM pg_catalog.pg_constraint con
      JOIN pg_catalog.pg_class cl ON cl.oid = con.conrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = cl.relnamespace
      CROSS JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS k(att, ord)
      JOIN pg_catalog.pg_attribute a
        ON a.attrelid = cl.oid AND a.attnum = k.att
     WHERE n.nspname = p_schema AND cl.relname = p_table
       AND con.contype = 'p';

    IF keys IS NULL THEN
        RAISE EXCEPTION
            'cannot audit %.%: it has no primary key to identify its rows',
            p_schema, p_table
            USING ERRCODE = 'XA010';
    END IF;

    -- Une colonne déclarée auditable qui n'existe pas est une faute de frappe,
    -- et une faute de frappe ici EXPURGE en silence la colonne qu'on voulait
    -- justement voir. Elle doit donc arrêter la migration.
    SELECT c INTO missing FROM unnest(p_columns) c
     WHERE NOT EXISTS (
       SELECT FROM pg_catalog.pg_attribute a
         JOIN pg_catalog.pg_class cl ON cl.oid = a.attrelid
         JOIN pg_catalog.pg_namespace n ON n.oid = cl.relnamespace
        WHERE n.nspname = p_schema AND cl.relname = p_table
          AND a.attname = c AND a.attnum > 0 AND NOT a.attisdropped);
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'column %.%.% does not exist', p_schema, p_table, missing
            USING ERRCODE = 'XA011';
    END IF;

    INSERT INTO audit.watched (schema_name, table_name, level, key_columns)
    VALUES (p_schema, p_table, p_level, keys)
    ON CONFLICT (schema_name, table_name)
      DO UPDATE SET level = excluded.level,
                    key_columns = excluded.key_columns,
                    removed_at = NULL;

    DELETE FROM audit.auditable_column
     WHERE schema_name = p_schema AND table_name = p_table;
    INSERT INTO audit.auditable_column (schema_name, table_name, column_name)
    SELECT p_schema, p_table, c FROM unnest(p_columns) c;

    EXECUTE format('DROP TRIGGER IF EXISTS zz_audit ON %I.%I', p_schema, p_table);
    -- zz_ : les déclencheurs se déclenchent dans l'ordre alphabétique du nom,
    -- et l'audit doit voir la ligne TELLE QU'ELLE SERA — après les gardes qui
    -- la corrigent, jamais avant.
    EXECUTE format(
        'CREATE TRIGGER zz_audit AFTER INSERT OR UPDATE OR DELETE ON %I.%I '
        'FOR EACH ROW EXECUTE FUNCTION audit.record()', p_schema, p_table);

    EXECUTE format('DROP TRIGGER IF EXISTS zz_audit_truncate ON %I.%I',
                   p_schema, p_table);
    -- TRUNCATE ne déclenche aucun trigger ligne à ligne : sans celui-ci,
    -- l'effacement le plus total serait le seul à ne rien laisser.
    EXECUTE format(
        'CREATE TRIGGER zz_audit_truncate AFTER TRUNCATE ON %I.%I '
        'FOR EACH STATEMENT EXECUTE FUNCTION audit.record()', p_schema, p_table);
END;
$$;

COMMENT ON FUNCTION audit.watch(name, name, name[], text) IS
'Déclare une table surveillée et pose ses déclencheurs. p_columns est la
LISTE BLANCHE : tout ce qui n''y figure pas est journalisé comme modifié mais
expurgé.';


-- --- Le journal est inaltérable -------------------------------------
CREATE FUNCTION audit.refuse_write()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% on %.% is refused: the audit log is a record',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'XA001';
END;
$$;

COMMENT ON FUNCTION audit.refuse_write() IS
'Un déclencheur plutôt qu''un GRANT retiré : un GRANT retiré ne lie pas une
connexion propriétaire, et c''est justement la session d''administration dont
on veut la trace.';

CREATE TRIGGER event_no_update BEFORE UPDATE ON audit.event
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_write();
CREATE TRIGGER event_no_delete BEFORE DELETE ON audit.event
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_write();


-- =====================================================================
--  4. CE QUI EST SURVEILLÉ DANS CETTE BASE
--
--  Hors liste blanche, donc expurgés partout : provision_key et
--  provider_id (l'identité chez Entra), les deux jti, kms_ref (le
--  pointeur vers la matière de signature), credential_id et public_key
--  de l'authentificateur, et challenge — un défi journalisé en clair
--  serait un défi rejouable.
-- =====================================================================

SELECT audit.watch('admin', 'user', '{id, created_at, deactivated_at}');

SELECT audit.watch('admin', 'identity', '{id, user_id, provider, created_at, bound_at}');

SELECT audit.watch('admin', 'session',
       '{id, user_id, created_at, absolute_expires_at, ended_at, end_reason}');

-- 'facts' : chaque appel fait tourner la paire. Les jti ne sont pas
-- déclarés, donc une rotation ne journalise que ce qui la date.
SELECT audit.watch('admin', 'token_pair',
       '{id, session_id, issued_at, inactivity_expires_at, replaced_at}', 'facts');

-- La clé de signature par admin : tout son cycle de vie est auditable,
-- sauf la référence KMS. public_jwk est publique par construction.
SELECT audit.watch('akeys', 'key',
       '{id, kid, user_id, session_id, state, public_jwk, created_at,
         activated_at, signs_until, published_until, private_destroyed_at}');

-- sign_count EST le signal de clonage : il doit être journalisé, sinon
-- l'invariant « strictement croissant » n'a pas d'historique pour se
-- défendre le jour où quelqu'un le conteste.
SELECT audit.watch('webauthn', 'authenticator',
       '{id, user_id, sign_count, label, created_at, revoked_at}');

-- Le défi lui-même reste hors liste. On journalise qu'un défi a été émis
-- pour telle action, jamais sa valeur.
SELECT audit.watch('webauthn', 'challenge',
       '{id, user_id, session_id, action, created_at, expires_at, consumed_at}');

SELECT audit.watch('admin', 'session_end_reason', '{code, deprecated_at}');
SELECT audit.watch('admin', 'identity_provider', '{code, deprecated_at}');
SELECT audit.watch('admin', 'retention', '{relation, keep_for, batch_size}');

SELECT audit.ensure_partitions(12);


-- =====================================================================
--  5. PRIVILÈGES
--
--  Le rôle applicatif n'a RIEN sur audit.event — ni lecture ni écriture.
--  Pas d'écriture, parce qu'un journal que l'appelant alimente est un
--  journal que l'appelant peut taire. Pas de lecture, parce qu'un rôle
--  applicatif capable de relire le journal de tous les tenants est une
--  fuite dont personne ne parle.
-- =====================================================================

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'admin_auditor') THEN
    CREATE ROLE admin_auditor LOGIN;
  END IF;
END $$;

COMMENT ON ROLE admin_auditor IS
'Lecture seule du journal. Un login séparé : celui qui relit un journal
d''audit ne doit pas être celui qui produit les événements dedans.';

GRANT USAGE ON SCHEMA audit TO admin_auditor;
GRANT SELECT ON audit.event, audit.watched, audit.auditable_column
    TO admin_auditor;

REVOKE ALL ON SCHEMA audit FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA audit FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA audit FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA audit
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Down Migration

DROP SCHEMA audit CASCADE;

DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'admin_auditor') THEN
    DROP OWNED BY admin_auditor;
    BEGIN
      DROP ROLE admin_auditor;
    EXCEPTION WHEN dependent_objects_still_exist
                OR dependent_privilege_descriptors_still_exist THEN
      RAISE NOTICE 'role admin_auditor kept: still referenced in this cluster';
    END;
  END IF;
END $$;
