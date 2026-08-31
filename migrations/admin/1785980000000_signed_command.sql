-- Up Migration

-- LA COMMANDE SIGNÉE, EN BASE.
--
-- Jusqu'ici le cloisonnement par tenant s'arrêtait au défi FIDO. Le défi
-- portait sa cible, mais la COMMANDE — l'acte lui-même — vivait entièrement
-- hors de la base. « La signature doit couvrir le tenant » était donc une
-- obligation de contrat que rien ne vérifiait, et c'était le seul endroit où
-- tout ce qui précède pouvait être défait par un bug applicatif.
--
--
-- POURQUOI CETTE TABLE N'EST PAS DANS LE SCHÉMA `audit`
--
-- C'en est, au sens où elle enregistre. Mais la modéliser comme de l'audit
-- coûterait exactement ce qui a de la valeur.
--
-- `audit.event` est écrit par un déclencheur AFTER : il CONSTATE. Il ne peut
-- rien refuser, par construction. Cette table-ci REFUSE — c'est sa raison
-- d'être — et trois refus sont hors de portée d'un journal :
--
--   · le rejeu, par un unique sur l'empreinte ;
--   · le détournement d'une preuve de présence, par un unique sur le défi ;
--   · l'incohérence entre la preuve et la cible, par le garde plus bas.
--
-- Et une raison concrète, décisive : la prémisse du schéma `audit` est que
-- l'application n'y écrit JAMAIS — aucun GRANT, tout par déclencheur. C'est
-- ce qui rend `audit.event` infalsifiable. Or cette table doit être écrite
-- par l'application, elle seule détenant la signature. Un
-- `GRANT INSERT ... ON audit.signed_command` détruirait la propriété qui
-- fait la valeur de tout le reste, et quiconque lirait cette ligne en
-- conclurait, à raison, que l'application peut écrire dans l'audit.
--
-- Donc : la CAUSE ici, dans admin. La CONSÉQUENCE dans audit — cette table
-- est surveillée, donc chaque commande laisse en plus une trace écrite par
-- déclencheur, que l'application ne peut ni forger ni omettre. Chacune fait
-- ce que l'autre ne peut pas.
--
--
-- CE QUE LA BASE NE PEUT PAS FAIRE
--
-- Elle ne VÉRIFIE PAS la signature. Pas d'ECDSA en base sans extension, et
-- pgcrypto ne sait pas le faire. Elle atteste que la commande DÉCLARAIT
-- telle cible, jamais que la signature est valide — c'est le service qui
-- vérifie, avec la clé publique que `akeys.key` publie. Ce que la base ferme,
-- c'est l'écart entre la preuve de présence et la déclaration, ce qui est
-- l'essentiel du trou.
--
-- Et l'empreinte DOIT couvrir un nonce, sinon deux commandes légitimes
-- identiques — révoquer le même droit deux fois, à un mois d'écart —
-- entrent en collision sur l'unique et la seconde est refusée comme un
-- rejeu. Conséquence directe du choix d'unicité, portée au contrat.
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD080  the command's target does not match the presence it spends
--     AD081  the presence was never proved, or has not been consumed
--     AD082  the signing key may not sign at the moment claimed
--     AD083  a command is a fact: it is never updated, never deleted
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

-- Les clés étrangères composites de cette base servent d'anti-blanchiment :
-- elles rendent impossible de rattacher l'objet d'un admin à la session d'un
-- autre. Ces deux uniques sont ce qui permet de continuer le motif ici.
ALTER TABLE webauthn.challenge
    ADD CONSTRAINT uq_challenge_owner UNIQUE (id, user_id, session_id);
ALTER TABLE akeys.key
    ADD CONSTRAINT uq_key_owner UNIQUE (id, user_id, session_id);


CREATE TABLE admin.signed_command (
    id             uuid        NOT NULL DEFAULT gen_random_uuid(),

    user_id        uuid        NOT NULL,
    session_id     uuid        NOT NULL,
    key_id         uuid        NOT NULL,
    challenge_id   uuid        NOT NULL,

    action         text        NOT NULL,
    scope          text        NOT NULL,
    target_tenant_id uuid,

    -- L'empreinte de la commande canonique, pas la commande. La base n'a
    -- aucun besoin de lire ce qui a été signé, et ne doit pas : le contenu
    -- d'une commande d'administration n'a rien à faire ici.
    command_digest bytea       NOT NULL,

    issued_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT signed_command_pk PRIMARY KEY (id),

    -- LE REJEU EST REFUSÉ PAR LE MOTEUR. Pas par une vérification applicative
    -- qu'un service pourrait sauter sous charge.
    CONSTRAINT uq_command_digest UNIQUE (command_digest),

    -- UNE PREUVE DE PRÉSENCE SE DÉPENSE SUR UNE COMMANDE. Sans cet unique,
    -- une touche matérielle légitime autoriserait la commande qu'on veut, et
    -- puis une seconde, et puis une troisième.
    CONSTRAINT uq_command_challenge UNIQUE (challenge_id),

    CONSTRAINT signed_command_session_fk
        FOREIGN KEY (session_id, user_id)
        REFERENCES admin.session (id, user_id) ON DELETE RESTRICT,
    -- Composites : le défi ET la clé appartiennent à CET admin dans CETTE
    -- session. Une commande ne peut pas emprunter la présence d'un autre.
    CONSTRAINT signed_command_challenge_fk
        FOREIGN KEY (challenge_id, user_id, session_id)
        REFERENCES webauthn.challenge (id, user_id, session_id) ON DELETE RESTRICT,
    CONSTRAINT signed_command_key_fk
        FOREIGN KEY (key_id, user_id, session_id)
        REFERENCES akeys.key (id, user_id, session_id) ON DELETE RESTRICT,

    CONSTRAINT signed_command_scope CHECK (scope IN ('TENANT', 'PLATFORM')),
    CONSTRAINT signed_command_target_matches_scope CHECK (
        (scope = 'TENANT'   AND target_tenant_id IS NOT NULL)
     OR (scope = 'PLATFORM' AND target_tenant_id IS NULL)),
    CONSTRAINT signed_command_digest_length CHECK (octet_length(command_digest) = 32)
);

CREATE INDEX signed_command_by_admin
    ON admin.signed_command (user_id, issued_at DESC);
CREATE INDEX signed_command_by_target
    ON admin.signed_command (target_tenant_id, issued_at DESC)
    WHERE target_tenant_id IS NOT NULL;

COMMENT ON TABLE admin.signed_command IS
'Toute action lourde, telle que l''admin l''a signée.

C''est une CAUSE, pas un journal : elle refuse le rejeu, refuse qu''une preuve
de présence serve deux fois, et refuse qu''une commande vise autre chose que
ce pour quoi la présence a été prouvée. Un journal ne peut rien refuser.

La trace, elle, est ailleurs : cette table est surveillée par le schéma
audit, donc chaque commande laisse en plus une ligne écrite par déclencheur
que l''application ne peut ni forger ni supprimer.';

COMMENT ON COLUMN admin.signed_command.command_digest IS
'SHA-256 de la commande canonique. DOIT couvrir un nonce : sans lui, deux
commandes légitimes identiques à un mois d''écart entrent en collision sur
uq_command_digest et la seconde est refusée comme un rejeu.';

COMMENT ON COLUMN admin.signed_command.key_id IS
'La clé qui a signé. La base ne vérifie pas la signature — impossible sans
extension — mais elle garantit que la clé citée appartenait à cet admin, dans
cette session, et pouvait signer à cet instant. Le service vérifie le reste
avec la clé publique que akeys.key publie.';


-- =====================================================================
--  LE GARDE QUI FERME LA BOUCLE
-- =====================================================================

CREATE FUNCTION admin.command_matches_presence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    ch  record;
    k   record;
BEGIN
    SELECT action, scope, target_tenant_id, consumed_at
      INTO ch
      FROM webauthn.challenge
     WHERE id = NEW.challenge_id;

    -- Une présence non consommée n'est pas une présence : le défi doit avoir
    -- été dépensé par verify_presence, qui est le seul endroit où le geste
    -- matériel est réellement constaté.
    IF ch.consumed_at IS NULL THEN
        RAISE EXCEPTION 'challenge % was never consumed', NEW.challenge_id
            USING ERRCODE = 'AD081';
    END IF;

    -- LE POINT DE TOUTE CETTE MIGRATION. Prouver sa présence pour le tenant A
    -- puis signer contre B devient impossible, au lieu d'être une obligation
    -- de contrat que personne ne vérifie.
    IF NEW.scope IS DISTINCT FROM ch.scope
    OR NEW.target_tenant_id IS DISTINCT FROM ch.target_tenant_id
    OR NEW.action IS DISTINCT FROM ch.action THEN
        RAISE EXCEPTION
            'command targets %/% but presence was proved for %/%',
            NEW.scope, coalesce(NEW.target_tenant_id::text, '(platform)'),
            ch.scope, coalesce(ch.target_tenant_id::text, '(platform)')
            USING ERRCODE = 'AD080';
    END IF;

    -- L'autorité est relue ICI aussi. verify_presence l'a déjà vérifiée à la
    -- consommation, mais une révocation peut tomber entre les deux — et c'est
    -- la commande qui produit l'effet, pas le défi.
    IF NOT admin.may_operate(NEW.user_id, NEW.target_tenant_id) THEN
        RAISE EXCEPTION 'admin % may not operate on %',
            NEW.user_id, coalesce(NEW.target_tenant_id::text, '(platform)')
            USING ERRCODE = 'AD080';
    END IF;

    SELECT state, activated_at, signs_until, private_destroyed_at
      INTO k
      FROM akeys.key
     WHERE id = NEW.key_id;

    IF k.private_destroyed_at IS NOT NULL
    OR k.activated_at IS NULL
    OR NEW.issued_at < k.activated_at
    OR NEW.issued_at >= k.signs_until THEN
        RAISE EXCEPTION 'key % could not sign at %', NEW.key_id, NEW.issued_at
            USING ERRCODE = 'AD082';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER signed_command_matches_presence
    BEFORE INSERT ON admin.signed_command
    FOR EACH ROW EXECUTE FUNCTION admin.command_matches_presence();


-- Une commande est un fait. On n'en réécrit pas la cible après coup, et on ne
-- la fait pas disparaître — c'est la moitié de l'intérêt de l'enregistrer.
CREATE FUNCTION admin.command_is_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% on admin.signed_command is refused: a command is a fact',
        TG_OP
        USING ERRCODE = 'AD083';
END;
$$;

CREATE TRIGGER signed_command_no_update BEFORE UPDATE ON admin.signed_command
    FOR EACH ROW EXECUTE FUNCTION admin.command_is_immutable();
CREATE TRIGGER signed_command_no_delete BEFORE DELETE ON admin.signed_command
    FOR EACH ROW EXECUTE FUNCTION admin.command_is_immutable();


-- =====================================================================
--  PRIVILÈGES ET AUDIT
-- =====================================================================

GRANT SELECT, INSERT ON admin.signed_command TO app_admin_plane;
REVOKE UPDATE, DELETE, TRUNCATE ON admin.signed_command FROM app_admin_plane;
REVOKE ALL ON FUNCTION admin.command_matches_presence() FROM PUBLIC;
REVOKE ALL ON FUNCTION admin.command_is_immutable() FROM PUBLIC;

-- command_digest est déclaré auditable : c'est une empreinte, pas un secret,
-- et c'est elle qui permet de recouper une ligne d'audit avec la commande
-- qu'un service a réellement vérifiée.
SELECT audit.watch('admin', 'signed_command',
       '{id, user_id, session_id, key_id, challenge_id, action, scope,
         target_tenant_id, command_digest, issued_at}');

-- Down Migration

DELETE FROM audit.auditable_column
 WHERE schema_name = 'admin' AND table_name = 'signed_command';
DELETE FROM audit.watched
 WHERE schema_name = 'admin' AND table_name = 'signed_command';

DROP TABLE admin.signed_command;
DROP FUNCTION admin.command_is_immutable();
DROP FUNCTION admin.command_matches_presence();

ALTER TABLE akeys.key DROP CONSTRAINT uq_key_owner;
ALTER TABLE webauthn.challenge DROP CONSTRAINT uq_challenge_owner;
