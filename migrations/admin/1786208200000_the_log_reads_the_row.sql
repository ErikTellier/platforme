-- Up Migration

-- LE JOURNAL N'A JAMAIS SU DE QUEL CLIENT IL PARLAIT.
--
--     nullif(current_setting('app.tenant', true), '')::uuid
--
-- `app.tenant`, au singulier. Les huit bases cloisonnées lisent
-- `app.tenant_id`, et personne n'a jamais posé `app.tenant` — ni le châssis,
-- ni le semis, ni un test. La colonne est donc restée vide depuis le premier
-- jour :
--
--     admin : 1 562 événements, 0 avec un tenant_id
--     ticket : 2 941 événements, 2 836 avec un tenant_id
--
-- C'est exactement le défaut que `check-coherence` a été écrit pour attraper —
-- son entête raconte « iam lisait app.tenant quand les quatre autres lisaient
-- app.tenant_id ». Il ne l'a pas vu ici parce que sa propriété ne regarde que
-- les bases cloisonnées, et celle-ci n'en est pas une. Une vérification qui
-- choisit qui elle inspecte finit par ne pas inspecter le fautif.
--
--
-- ═══ RENOMMER SERAIT LA MAUVAISE CORRECTION ═══
--
-- Poser `app.tenant_id` réintroduirait une liaison de session de client dans
-- une base qui n'en a pas et n'en veut pas : ici le client n'est pas un
-- contexte, c'est une COLONNE de la ligne. Exiger un réglage avant chaque
-- écriture obligerait un opérateur de plateforme à choisir un client pour
-- agir sur la plateforme, et transformerait une console en formulaire.
--
-- Le déclencheur a déjà la ligne sous la main. Il lit le client DESSUS —
-- `tenant_id` ou `target_tenant_id` selon la table — et il ne peut donc plus
-- l'oublier : il n'y a plus rien à lier.
--
-- Une écriture qui ne concerne aucun client (une session, une clé, un compte)
-- laisse la colonne vide, et c'est juste : elle ne parle d'aucun client.
-- Un TRUNCATE aussi — il n'en vise pas un en particulier.
--
--
-- ═══ CE QUE ÇA DÉBLOQUE ═══
--
-- « Montrez-moi tout ce que vos opérateurs ont fait sur notre périmètre » —
-- la question qui suit immédiatement celle sur la résidence — devient une
-- requête. Et la rétention par détachement de partitions peut enfin trier par
-- client.
--
-- L'HISTORIQUE N'EST PAS RÉÉCRIT. Les lignes déjà là gardent leur NULL : il
-- dit la vérité, personne n'a enregistré ce client. Le déduire aujourd'hui
-- serait fabriquer un fait d'audit, ce qu'un journal ne doit jamais faire.
--
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE OR REPLACE FUNCTION audit.record()
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

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT coalesce(array_agg(column_name), '{}'::name[]) INTO allowed
      FROM audit.auditable_column
     WHERE schema_name = TG_TABLE_SCHEMA AND table_name = TG_TABLE_NAME;

    IF TG_OP = 'TRUNCATE' THEN
        INSERT INTO audit.event (actor, tenant_id, schema_name, table_name, op)
        -- Un TRUNCATE ne vise aucun client en particulier : la colonne
        -- reste vide, et c'est la vérité.
        VALUES (nullif(current_setting('app.caller', true), ''), NULL,
                TG_TABLE_SCHEMA, TG_TABLE_NAME, 'TRUNCATE');
        RETURN NULL;
    END IF;

    before_row := CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END;
    after_row  := CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END;
    shape      := coalesce(after_row, before_row);

    FOR col IN SELECT jsonb_object_keys(shape) LOOP
        b := before_row -> col;
        a := after_row  -> col;
        CONTINUE WHEN TG_OP = 'UPDATE' AND b IS NOT DISTINCT FROM a;

        IF col::name = ANY (allowed) THEN
            changed := changed || jsonb_build_object(
                col, jsonb_build_object('before', b, 'after', a));
        ELSE
            changed := changed || jsonb_build_object(
                col, jsonb_build_object('redacted', true));
        END IF;
    END LOOP;

    IF TG_OP = 'UPDATE' AND w.level = 'facts'
       AND NOT EXISTS (SELECT FROM jsonb_object_keys(changed) k
                        WHERE k::name = ANY (allowed)) THEN
        RETURN NULL;
    END IF;

    FOREACH kc IN ARRAY w.key_columns LOOP
        IF kc = ANY (allowed) THEN
            keys := keys || jsonb_build_object(kc, shape -> kc::text);
        ELSE
            raw := shape ->> kc::text;
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
        -- LE CLIENT VIENT DE LA LIGNE, pas d'un réglage que personne ne pose.
        -- Deux noms parce que deux sens : `tenant_id` quand la ligne
        -- APPARTIENT au client, `target_tenant_id` quand elle le VISE.
        coalesce(shape ->> 'tenant_id', shape ->> 'target_tenant_id')::uuid,
        TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP, keys, changed);

    RETURN NULL;
END;
$$;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

CREATE OR REPLACE FUNCTION audit.record()
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

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT coalesce(array_agg(column_name), '{}'::name[]) INTO allowed
      FROM audit.auditable_column
     WHERE schema_name = TG_TABLE_SCHEMA AND table_name = TG_TABLE_NAME;

    IF TG_OP = 'TRUNCATE' THEN
        INSERT INTO audit.event (actor, tenant_id, schema_name, table_name, op)
        VALUES (nullif(current_setting('app.caller', true), ''),
                nullif(current_setting('app.tenant', true), '')::uuid,
                TG_TABLE_SCHEMA, TG_TABLE_NAME, 'TRUNCATE');
        RETURN NULL;
    END IF;

    before_row := CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END;
    after_row  := CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END;
    shape      := coalesce(after_row, before_row);

    FOR col IN SELECT jsonb_object_keys(shape) LOOP
        b := before_row -> col;
        a := after_row  -> col;
        CONTINUE WHEN TG_OP = 'UPDATE' AND b IS NOT DISTINCT FROM a;

        IF col::name = ANY (allowed) THEN
            changed := changed || jsonb_build_object(
                col, jsonb_build_object('before', b, 'after', a));
        ELSE
            changed := changed || jsonb_build_object(
                col, jsonb_build_object('redacted', true));
        END IF;
    END LOOP;

    IF TG_OP = 'UPDATE' AND w.level = 'facts'
       AND NOT EXISTS (SELECT FROM jsonb_object_keys(changed) k
                        WHERE k::name = ANY (allowed)) THEN
        RETURN NULL;
    END IF;

    FOREACH kc IN ARRAY w.key_columns LOOP
        IF kc = ANY (allowed) THEN
            keys := keys || jsonb_build_object(kc, shape -> kc::text);
        ELSE
            raw := shape ->> kc::text;
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
        nullif(current_setting('app.tenant', true), '')::uuid,
        TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP, keys, changed);

    RETURN NULL;
END;
$$;

RESET ROLE;
