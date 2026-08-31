-- Up Migration

-- UNE TOUCHE, UNE COMMANDE — ET PRÉPARER UN CLIENT EN DEMANDAIT QUARANTE.
--
-- `uq_command_challenge UNIQUE (challenge_id)` dit « une preuve de présence se
-- dépense sur UNE commande », et la migration qui l'a posé explique pourquoi :
-- « sans cet unique, une touche matérielle légitime autoriserait la commande
-- qu'on veut, et puis une seconde, et puis une troisième ».
--
-- L'attaque visée est réelle : une touche obtenue pour X, réutilisée pour Y.
-- Mais elle suppose que la seconde commande soit INCONNUE au moment de la
-- touche. Préparer un client ne ressemble pas à ça : on écrit la liste, on la
-- relit, on la signe. Rien n'est découvert après coup.
--
-- L'invariant se DÉPLACE donc, il ne disparaît pas :
--
--     avant   une touche → une commande
--     après   une touche → UN LOT FIGÉ, dont on connaît le contenu exact
--
-- Ce qui est attesté devient « exactement ces N commandes, dans cet ordre,
-- sur ce client » — au fond plus fort qu'avant, puisque le contenu entier est
-- engagé au lieu d'une seule ligne.
--
--
-- ═══ CE QUI REND LE LOT INEXTENSIBLE ═══
--
-- Trois choses, et il faut les trois :
--
--   `manifest_digest` — l'empreinte de la liste canonique. Elle dit CE QUI
--                       était prévu.
--   `declared_count`  — combien. Sans lui, l'empreinte engage un contenu que
--                       personne ne recompte : on pourrait ajouter une
--                       vingt-et-unième commande à un lot qui en déclarait
--                       vingt, et rien ne le verrait (AD112).
--   la portée du lot  — un lot vise UN client, ou la plateforme. Mélanger deux
--                       clients dans une signature ferait d'une touche pour
--                       Acme une autorisation chez son concurrent (AD111).
--
--
-- ═══ CE QUE LA BASE NE PEUT PAS FAIRE, ET QUI COMPTE PLUS QUE TOUT ═══
--
-- Une touche WebAuthn N'AFFICHE RIEN. Le navigateur dit « authentifiez-vous »,
-- jamais « vous suspendez le client Acme ». C'est déjà vrai aujourd'hui : le
-- triplet action/portée/cible du défi est une métadonnée que le SERVEUR
-- vérifie, pas quelque chose qu'un humain lit.
--
-- Le seul contrôle humain réel est donc ce que l'outil AFFICHE avant de
-- demander la touche. Et le piège est là : si l'outil montre un texte lisible
-- et hache autre chose — un JSON réordonné, une clé normalisée, un espace de
-- plus — la signature n'atteste plus rien de ce qui a été lu.
--
--   LES OCTETS AFFICHÉS DOIVENT ÊTRE LES OCTETS HACHÉS.
--
-- Une sérialisation canonique, une seule, montrée telle quelle. C'est laid à
-- l'écran, et c'est le point. La base ne peut pas le vérifier — elle ne voit
-- qu'une empreinte — donc c'est porté au contrat.
--
--
-- ═══ CE QUI NE CHANGE PAS ═══
--
-- L'autorité reste relue à CHAQUE commande, pas au lot. Une révocation qui
-- tombe au milieu d'une préparation mord sur les commandes restantes. Un lot
-- peut donc échouer en cours pour une raison qui n'est pas une erreur de son
-- auteur — et `admin.batch_incomplete` est là pour que ça se voie.
--
-- Et l'empreinte par commande reste unique : deux commandes identiques dans
-- deux lots différents entreraient en collision sur `uq_command_digest`.
-- L'aléa que le contrat impose devient donc « identifiant du lot + rang »,
-- ce qui est plus simple que ce qu'il faudrait inventer autrement.
--
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD110  the batch's presence is not a signature of this batch
--     AD111  the command does not belong to the batch it names
--     AD112  the batch is full: the manifest declared fewer commands
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

INSERT INTO admin.command_action (code, description, applies_to) VALUES
  ('batch.sign', 'Signer un lot de commandes déclaré à l''avance.', 'ANY')
ON CONFLICT (code) DO NOTHING;


CREATE TABLE admin.command_batch (
    id             uuid        NOT NULL DEFAULT gen_random_uuid(),

    user_id        uuid        NOT NULL,
    session_id     uuid        NOT NULL,
    challenge_id   uuid        NOT NULL,

    -- LE LOT VISE UN SEUL CLIENT. Mélanger deux clients dans une signature
    -- ferait d'une touche pour Acme une autorisation chez son concurrent.
    scope          text        NOT NULL,
    target_tenant_id uuid,

    -- L'empreinte de la liste CANONIQUE, celle-là même que l'outil a affichée.
    manifest_digest bytea      NOT NULL,
    declared_count int         NOT NULL,

    issued_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT command_batch_pk PRIMARY KEY (id),

    -- L'INVARIANT DÉPLACÉ. C'était `uq_command_challenge` sur la commande ;
    -- c'est ici désormais : une touche, un lot.
    CONSTRAINT uq_batch_challenge UNIQUE (challenge_id),
    CONSTRAINT uq_batch_digest UNIQUE (manifest_digest),

    CONSTRAINT command_batch_session_fk
        FOREIGN KEY (session_id, user_id)
        REFERENCES admin.session (id, user_id) ON DELETE RESTRICT,
    CONSTRAINT command_batch_challenge_fk
        FOREIGN KEY (challenge_id, user_id, session_id)
        REFERENCES webauthn.challenge (id, user_id, session_id) ON DELETE RESTRICT,

    CONSTRAINT command_batch_scope CHECK (scope IN ('TENANT', 'PLATFORM')),
    CONSTRAINT command_batch_target_matches_scope CHECK (
        (scope = 'TENANT'   AND target_tenant_id IS NOT NULL) OR
        (scope = 'PLATFORM' AND target_tenant_id IS NULL)),
    CONSTRAINT command_batch_digest_length CHECK (
        octet_length(manifest_digest) = 32),
    CONSTRAINT command_batch_count_positive CHECK (declared_count > 0)
);

CREATE INDEX ix_command_batch_user ON admin.command_batch (user_id, issued_at);

COMMENT ON TABLE admin.command_batch IS
'Un lot de commandes déclaré à l''avance, signé par UNE touche.

Préparer un client demandait quarante touches parce que l''invariant était
« une preuve de présence, une commande ». Il n''a pas disparu : il porte
désormais sur le lot. Ce qui est attesté est « exactement ces N commandes, dans
cet ordre, sur ce client » — plus fort qu''avant, puisque le contenu entier est
engagé.';

COMMENT ON COLUMN admin.command_batch.manifest_digest IS
'L''empreinte de la liste canonique — CELLE QUE L''OUTIL A AFFICHÉE. Une touche
WebAuthn ne montre rien à l''humain : le seul contrôle réel est ce qui est lu
avant de toucher. Si l''outil affiche un texte et hache autre chose, cette
colonne n''atteste plus rien. La base ne peut pas le vérifier ; le contrat le
porte.';

COMMENT ON COLUMN admin.command_batch.declared_count IS
'Combien de commandes le manifeste annonçait. Sans ce nombre, l''empreinte
engage un contenu que personne ne recompte : on ajouterait une vingt-et-unième
commande à un lot qui en déclarait vingt, et rien ne le verrait (AD112).';


-- =====================================================================
--  LA COMMANDE APPARTIENT AU LOT, OU PORTE SON PROPRE DÉFI
-- =====================================================================

ALTER TABLE admin.signed_command
    ADD COLUMN batch_id uuid REFERENCES admin.command_batch (id)
        ON DELETE RESTRICT,
    ADD COLUMN batch_seq int,
    ALTER COLUMN challenge_id DROP NOT NULL;

-- L'un OU l'autre, jamais les deux, jamais aucun. Une commande sans preuve
-- d'aucune sorte est précisément ce que `signed_command` refuse d'être.
ALTER TABLE admin.signed_command
    ADD CONSTRAINT signed_command_one_proof CHECK (
        (challenge_id IS NOT NULL AND batch_id IS NULL AND batch_seq IS NULL)
     OR (challenge_id IS NULL AND batch_id IS NOT NULL AND batch_seq IS NOT NULL));

-- L'unique d'origine devient partiel : il ne parle plus que des commandes qui
-- portent leur propre défi.
ALTER TABLE admin.signed_command DROP CONSTRAINT uq_command_challenge;
CREATE UNIQUE INDEX uq_command_challenge
    ON admin.signed_command (challenge_id) WHERE challenge_id IS NOT NULL;

-- Le rang est unique dans son lot : deux commandes ne peuvent pas prétendre
-- occuper la même ligne du manifeste.
CREATE UNIQUE INDEX uq_command_batch_seq
    ON admin.signed_command (batch_id, batch_seq) WHERE batch_id IS NOT NULL;

COMMENT ON COLUMN admin.signed_command.batch_id IS
'Le lot dont cette commande fait partie, quand elle n''a pas son propre défi.
`signed_command_one_proof` impose l''un ou l''autre : une commande sans preuve
d''aucune sorte est exactement ce que cette table refuse d''être.';

COMMENT ON COLUMN admin.signed_command.batch_seq IS
'Le rang dans le manifeste. Il sert aussi d''aléa : `uq_command_digest`
s''applique toujours ligne à ligne, donc deux commandes identiques dans deux
lots entreraient en collision. « identifiant du lot + rang » est l''aléa le plus
simple à produire, et le contrat l''impose déjà sous une autre forme.';


CREATE FUNCTION admin.batch_is_signed()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    ch record;
BEGIN
    SELECT consumed_at, action, scope, target_tenant_id
      INTO ch
      FROM webauthn.challenge
     WHERE id = NEW.challenge_id;

    IF NOT FOUND OR ch.consumed_at IS NULL THEN
        RAISE EXCEPTION 'challenge % was never proved, or not consumed',
            NEW.challenge_id
            USING ERRCODE = 'AD110';
    END IF;

    -- `IS DISTINCT FROM` couvre déjà le cas NULL des deux côtés : une clause
    -- supplémentaire pour « l'un est NULL et l'autre non » serait subsumée,
    -- donc morte, donc trompeuse à la relecture.
    IF ch.action <> 'batch.sign'
    OR ch.scope  IS DISTINCT FROM NEW.scope
    OR ch.target_tenant_id IS DISTINCT FROM NEW.target_tenant_id THEN
        RAISE EXCEPTION
            'the presence proved is not a batch signature for (%, %)',
            NEW.scope, coalesce(NEW.target_tenant_id::text, '(platform)')
            USING ERRCODE = 'AD110',
                  HINT = 'A batch is signed by a challenge whose action is '
                         'batch.sign, on the same perimeter.';
    END IF;

    -- L'autorité, au moment de signer. Elle sera relue à chaque commande.
    IF NOT admin.may_operate(NEW.user_id, NEW.target_tenant_id) THEN
        RAISE EXCEPTION 'admin % may not operate on %',
            NEW.user_id, coalesce(NEW.target_tenant_id::text, '(platform)')
            USING ERRCODE = 'AD110';
    END IF;

    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION admin.batch_is_signed() FROM PUBLIC;

CREATE TRIGGER command_batch_is_signed
    BEFORE INSERT ON admin.command_batch
    FOR EACH ROW EXECUTE FUNCTION admin.batch_is_signed();

-- UN LOT EST UN FAIT, comme les commandes qu'il porte. Repointer un manifeste
-- après coup, ou effacer le lot en laissant ses commandes, ferait mentir la
-- seule chose qu'il atteste : ce qui avait été prévu. Même code que
-- `signed_command`, parce que c'est le même refus.
CREATE TRIGGER command_batch_no_update BEFORE UPDATE ON admin.command_batch
    FOR EACH ROW EXECUTE FUNCTION admin.command_is_immutable();
CREATE TRIGGER command_batch_no_delete BEFORE DELETE ON admin.command_batch
    FOR EACH ROW EXECUTE FUNCTION admin.command_is_immutable();


CREATE FUNCTION admin.command_belongs_to_its_batch()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    b    record;
    used int;
BEGIN
    IF NEW.batch_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT user_id, session_id, scope, target_tenant_id, declared_count
      INTO b
      FROM admin.command_batch WHERE id = NEW.batch_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'batch % does not exist', NEW.batch_id
            USING ERRCODE = 'AD111';
    END IF;

    -- MÊME OPÉRATEUR, MÊME SESSION, MÊME PÉRIMÈTRE. Sans ces trois égalités,
    -- une touche pour un client autoriserait une écriture chez un autre — le
    -- trou que le lot est censé ne pas rouvrir.
    IF b.user_id <> NEW.user_id
    OR b.session_id <> NEW.session_id
    OR b.scope <> NEW.scope
    OR b.target_tenant_id IS DISTINCT FROM NEW.target_tenant_id THEN
        RAISE EXCEPTION
            'this command does not belong to the batch it names'
            USING ERRCODE = 'AD111',
                  HINT = 'NEVER RETRY, AND ALERT. A batch signs one perimeter, '
                         'for one operator, in one session.';
    END IF;

    IF NEW.batch_seq > b.declared_count THEN
        RAISE EXCEPTION 'the manifest declared % commands, this one is #%',
            b.declared_count, NEW.batch_seq
            USING ERRCODE = 'AD112';
    END IF;

    SELECT count(*) INTO used
      FROM admin.signed_command WHERE batch_id = NEW.batch_id;

    IF used >= b.declared_count THEN
        RAISE EXCEPTION 'the manifest declared % commands, and they are written',
            b.declared_count
            USING ERRCODE = 'AD112',
                  HINT = 'The digest commits WHAT was planned; the count commits '
                         'HOW MANY. Without the second, a batch could be '
                         'extended after the touch.';
    END IF;

    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION admin.command_belongs_to_its_batch() FROM PUBLIC;

-- `aaa_` : AVANT `command_matches_presence`, qui exige un défi consommé et n'en
-- trouverait pas sur une commande de lot.
CREATE TRIGGER aaa_signed_command_belongs_to_its_batch
    BEFORE INSERT ON admin.signed_command
    FOR EACH ROW EXECUTE FUNCTION admin.command_belongs_to_its_batch();


-- La garde d'origine ne parle plus que des commandes à défi propre.
CREATE OR REPLACE FUNCTION admin.command_matches_presence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    ch record;
    k  record;
BEGIN
    -- Une commande de lot a déjà été vérifiée contre son lot, dont le défi est
    -- le seul et unique. Repasser ici chercherait un défi qui n'existe pas.
    IF NEW.batch_id IS NULL THEN
        SELECT consumed_at, action, scope, target_tenant_id
          INTO ch
          FROM webauthn.challenge
         WHERE id = NEW.challenge_id;

        IF NOT FOUND OR ch.consumed_at IS NULL THEN
            RAISE EXCEPTION 'challenge % was never proved, or not consumed',
                NEW.challenge_id
                USING ERRCODE = 'AD081';
        END IF;

        IF ch.action IS DISTINCT FROM NEW.action
        OR ch.scope  IS DISTINCT FROM NEW.scope
        OR ch.target_tenant_id IS DISTINCT FROM NEW.target_tenant_id THEN
            RAISE EXCEPTION
                'command (%, %, %) does not match the presence proved for (%, %, %)',
                NEW.action, NEW.scope, NEW.target_tenant_id,
                ch.action, ch.scope, ch.target_tenant_id
                USING ERRCODE = 'AD080';
        END IF;
    END IF;

    -- L'AUTORITÉ EST RELUE À CHAQUE COMMANDE, y compris dans un lot. Une
    -- révocation qui tombe au milieu d'une préparation mord sur les commandes
    -- restantes : c'est la commande qui produit l'effet, pas la signature.
    IF NOT admin.may_operate(NEW.user_id, NEW.target_tenant_id) THEN
        RAISE EXCEPTION 'admin % may not operate on %',
            NEW.user_id, coalesce(NEW.target_tenant_id::text, '(platform)')
            USING ERRCODE = 'AD080';
    END IF;

    SELECT k2.state, k2.activated_at, k2.signs_until, k2.private_destroyed_at,
           s.ended_at
      INTO k
      FROM akeys.key k2
      JOIN admin.session s ON s.id = k2.session_id
     WHERE k2.id = NEW.key_id;

    IF k.private_destroyed_at IS NOT NULL
    OR k.activated_at IS NULL
    OR k.ended_at IS NOT NULL
    OR NEW.issued_at < k.activated_at
    OR NEW.issued_at >= k.signs_until THEN
        RAISE EXCEPTION 'key % could not sign at %', NEW.key_id, NEW.issued_at
            USING ERRCODE = 'AD082';
    END IF;

    RETURN NEW;
END;
$$;


-- =====================================================================
--  CE QUE LA CONSOLE MONTRE
-- =====================================================================

CREATE VIEW admin.batch_estate
    WITH (security_invoker = TRUE)
AS
SELECT b.id, b.user_id, b.scope, b.target_tenant_id, b.issued_at,
       b.declared_count,
       count(c.id)                       AS written,
       b.declared_count - count(c.id)    AS missing
  FROM admin.command_batch AS b
  LEFT JOIN admin.signed_command AS c ON b.id = c.batch_id
 GROUP BY b.id;

COMMENT ON VIEW admin.batch_estate IS
'Chaque lot, ce qu''il annonçait et ce qui a été écrit. La lecture qu''on ouvre
après une préparation pour savoir si elle est allée au bout.';

CREATE VIEW admin.batch_incomplete
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, scope, target_tenant_id, issued_at, declared_count, written,
         missing
    FROM admin.batch_estate
   WHERE missing > 0;

COMMENT ON VIEW admin.batch_incomplete IS
'Les lots signés dont toutes les commandes n''ont pas abouti. L''autorité étant
relue à CHAQUE commande, une révocation tombée en cours de préparation laisse
un lot à moitié écrit — et c''est la seule façon de s''en apercevoir autrement
qu''en recomptant à la main.';

CREATE VIEW api.command_batch AS
  SELECT id, user_id, session_id, challenge_id, scope, target_tenant_id,
         manifest_digest, declared_count, issued_at
    FROM admin.command_batch;
CREATE VIEW api.batch_estate AS
  SELECT id, user_id, scope, target_tenant_id, issued_at, declared_count, written,
         missing
    FROM admin.batch_estate;
CREATE VIEW api.batch_incomplete AS
  SELECT id, user_id, scope, target_tenant_id, issued_at, declared_count, written,
         missing
    FROM admin.batch_incomplete;

GRANT SELECT, INSERT ON api.command_batch TO app_admin_plane;
GRANT SELECT ON api.batch_estate, api.batch_incomplete TO app_admin_plane;

SELECT audit.watch('admin', 'command_batch',
       '{id, user_id, session_id, challenge_id, scope, target_tenant_id,
         declared_count, issued_at}');

INSERT INTO audit.auditable_column (schema_name, table_name, column_name)
VALUES ('admin', 'signed_command', 'batch_id'),
       ('admin', 'signed_command', 'batch_seq');

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DELETE FROM audit.auditable_column
 WHERE schema_name = 'admin' AND table_name = 'signed_command'
   AND column_name IN ('batch_id', 'batch_seq');
DELETE FROM audit.auditable_column
 WHERE schema_name = 'admin' AND table_name = 'command_batch';
DELETE FROM audit.watched
 WHERE schema_name = 'admin' AND table_name = 'command_batch';

DROP VIEW api.batch_incomplete;
DROP VIEW api.batch_estate;
DROP VIEW api.command_batch;
DROP VIEW admin.batch_incomplete;
DROP VIEW admin.batch_estate;

CREATE OR REPLACE FUNCTION admin.command_matches_presence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    ch record;
    k  record;
BEGIN
    SELECT consumed_at, action, scope, target_tenant_id
      INTO ch
      FROM webauthn.challenge
     WHERE id = NEW.challenge_id;

    IF NOT FOUND OR ch.consumed_at IS NULL THEN
        RAISE EXCEPTION 'challenge % was never proved, or not consumed',
            NEW.challenge_id
            USING ERRCODE = 'AD081';
    END IF;

    IF ch.action IS DISTINCT FROM NEW.action
    OR ch.scope  IS DISTINCT FROM NEW.scope
    OR ch.target_tenant_id IS DISTINCT FROM NEW.target_tenant_id THEN
        RAISE EXCEPTION
            'command (%, %, %) does not match the presence proved for (%, %, %)',
            NEW.action, NEW.scope, NEW.target_tenant_id,
            ch.action, ch.scope, ch.target_tenant_id
            USING ERRCODE = 'AD080';
    END IF;

    IF NOT admin.may_operate(NEW.user_id, NEW.target_tenant_id) THEN
        RAISE EXCEPTION 'admin % may not operate on %',
            NEW.user_id, coalesce(NEW.target_tenant_id::text, '(platform)')
            USING ERRCODE = 'AD080';
    END IF;

    SELECT k2.state, k2.activated_at, k2.signs_until, k2.private_destroyed_at,
           s.ended_at
      INTO k
      FROM akeys.key k2
      JOIN admin.session s ON s.id = k2.session_id
     WHERE k2.id = NEW.key_id;

    IF k.private_destroyed_at IS NOT NULL
    OR k.activated_at IS NULL
    OR k.ended_at IS NOT NULL
    OR NEW.issued_at < k.activated_at
    OR NEW.issued_at >= k.signs_until THEN
        RAISE EXCEPTION 'key % could not sign at %', NEW.key_id, NEW.issued_at
            USING ERRCODE = 'AD082';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER aaa_signed_command_belongs_to_its_batch ON admin.signed_command;
DROP FUNCTION admin.command_belongs_to_its_batch();
DROP TRIGGER command_batch_no_delete ON admin.command_batch;
DROP TRIGGER command_batch_no_update ON admin.command_batch;
DROP TRIGGER command_batch_is_signed ON admin.command_batch;
DROP FUNCTION admin.batch_is_signed();

DROP INDEX admin.uq_command_batch_seq;
DROP INDEX admin.uq_command_challenge;

ALTER TABLE admin.signed_command
    DROP CONSTRAINT signed_command_one_proof,
    DROP COLUMN batch_seq,
    DROP COLUMN batch_id;

ALTER TABLE admin.signed_command
    ALTER COLUMN challenge_id SET NOT NULL,
    ADD CONSTRAINT uq_command_challenge UNIQUE (challenge_id);

DROP TABLE admin.command_batch;

ALTER TABLE admin.command_action DISABLE TRIGGER command_action_no_delete;
DELETE FROM admin.command_action c
 WHERE c.code = 'batch.sign'
   AND NOT EXISTS (SELECT FROM webauthn.challenge AS x WHERE x.action = c.code)
   AND NOT EXISTS (SELECT FROM admin.signed_command AS x WHERE x.action = c.code);
ALTER TABLE admin.command_action ENABLE TRIGGER command_action_no_delete;

RESET ROLE;
