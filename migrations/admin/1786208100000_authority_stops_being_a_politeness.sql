-- Up Migration

-- L'AUTORITÉ CESSE D'ÊTRE UNE POLITESSE.
--
-- `may_operate` existe depuis le début et dit la vérité. Rien ne l'appelait sur
-- le chemin de LECTURE. Un opérateur porteur d'une portée sur le client A
-- lisait les commandes signées, les usurpations et les portées du client B — il
-- suffisait d'écrire le SELECT. La fonction était une politesse que le code
-- s'imposait, pas une frontière que le moteur tenait.
--
-- Un auditeur de grand groupe ne demande pas si le code filtre. Il demande ce
-- qui se passe QUAND le code se trompe. C'est la seule question qui distingue
-- une garantie d'une intention.
--
-- Deux frontières, et elles ne se recouvrent pas :
--
--   L'AUTORITÉ   — cet opérateur porte-t-il une portée vivante sur ce client ?
--                  `may_operate`, désormais sur le chemin de lecture.
--
--   LA RÉSIDENCE — a-t-il le droit d'ouvrir CETTE juridiction ? Une portée
--                  accordée par erreur sur un client allemand ne suffit pas à
--                  un opérateur sans rattachement européen. Second verrou,
--                  indépendant, qu'aucun octroi d'autorité n'ouvre.
--
-- La résidence est vérifiée AVANT l'autorité : un refus de juridiction n'a pas
-- à révéler si la portée existait.
--
--
-- ═══ CE QUE `FORCE` ACHÈTE ICI, ET CE QU'IL N'ACHÈTE PAS ═══
--
-- La doctrine impose `FORCE` dès qu'une table active la RLS, et elle a raison :
-- `ENABLE` seul laisse passer le propriétaire, donc toute migration et toute
-- connexion d'exploitation.
--
-- Mais `admin_owner` est aussi le rôle sous lequel tournent les fonctions
-- `SECURITY DEFINER` — `validate_bearer`, `rotate_pair`, `verify_presence`,
-- `pair_emission_guard` et six autres. Les soumettre aux politiques les rend
-- AVEUGLES : elles ne voient plus la session qu'elles doivent valider.
--
--   Mesuré : sans politique pour le propriétaire, l'écriture d'une paire lève
--   « session does not exist » et `validate_bearer` rend zéro ligne. Plus
--   personne ne se connecte, et chaque requête est rejetée.
--
-- Il y a donc une politique explicite `TO admin_owner` par table. Elle rend au
-- propriétaire ce que `FORCE` lui retire — mais VISIBLEMENT, table par table,
-- dans `pg_policy`. Un auditeur lit la liste des chemins de confiance au lieu
-- de la deviner.
--
-- Ce que la migration achète réellement, et il faut le dire net : le
-- cloisonnement s'applique à `app_admin_plane`, LE RÔLE SOUS LEQUEL
-- L'APPLICATION SE CONNECTE. Le chemin propriétaire reste ce qu'il a toujours
-- été : des fonctions écrites dans ce schéma, dont `EXECUTE` est retiré à
-- `PUBLIC`. Le trou fermé est celui qui existait ; aucun autre n'est promis.
--
--
-- ═══ POURQUOI `audit.event` N'EST PAS TOUCHÉE ═══
--
-- Vérifié plutôt que supposé : `app_admin_plane` n'a AUCUN droit sur `audit.*`.
-- Seul `admin_auditor` y lit, et il doit tout lire. Une politique de
-- cloisonnement y viserait un rôle qui ne peut pas ouvrir la table — une
-- politique morte, c'est-à-dire une protection qu'on croit avoir.
--
--
-- ═══ LA RÉSIDENCE EST UN FAIT, PAS UN RÉGLAGE ═══
--
-- Déplacer un client d'une juridiction à l'autre n'est pas un UPDATE : c'est un
-- export, un consentement, parfois une notification à une autorité de contrôle.
-- Le schéma refuse de faire passer ça pour un réglage (AD102).
--
-- Et le défaut de `may_reside` est le REFUS : un client sans résidence déclarée
-- est fermé, pas ouvert. `tenant_without_residency` liste donc des accès
-- CASSÉS plutôt que des accès trop larges — l'erreur du bon côté, et la seule
-- qui ne se retourne pas contre le client.
--
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD100  no admin is bound to this session
--     AD101  a residency declaration is signed, like the rest
--     AD102  a tenant's residency is a fact, not a setting
--     AD103  a residency is never deleted, and only its revocation is written
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- =====================================================================
--  1. QUI AGIT
--
--  `app.caller` nomme le SERVICE. Il ne dit pas quel humain opère derrière,
--  et c'est bien : un service n'a pas d'autorité, il en porte une.
--
--  `app.admin` est cet humain. Le service le lie PAR TRANSACTION, depuis le
--  jeton qu'il vient de valider — jamais depuis un paramètre de requête.
-- =====================================================================

CREATE FUNCTION admin.app_admin() RETURNS uuid
    LANGUAGE plpgsql STABLE
    SET search_path TO ''
AS $$
DECLARE
    raw text;
BEGIN
    raw := nullif(current_setting('app.admin', true), '');
    IF raw IS NULL THEN
        RAISE EXCEPTION 'no admin is bound to this session'
            USING ERRCODE = 'AD100',
                  HINT = 'Bind app.admin per transaction, from the token you '
                         'just validated. A missing binding is a bug in the '
                         'caller, never a reason to widen what is visible.';
    END IF;
    RETURN raw::uuid;
END;
$$;

COMMENT ON FUNCTION admin.app_admin() IS
'L''opérateur humain de la transaction courante.

LÈVE plutôt que de rendre NULL. Un NULL se propagerait dans les politiques
comme un « aucune ligne » silencieux, et zéro ligne sur une console
d''administration se lit « ce client n''a rien » — la conclusion la plus
dangereuse qu''une console puisse suggérer.

Le troisième argument de set_config vaut true : la portée est la TRANSACTION.
Sans lui, une connexion recyclée par le pool porterait l''opérateur précédent,
et la RLS filtrerait pour quelqu''un d''autre.';


-- =====================================================================
--  2. LA RÉSIDENCE
-- =====================================================================

INSERT INTO admin.command_action (code, description, applies_to) VALUES
  ('residency.declare', 'Déclarer sous quel droit vivent les données d''un client.', 'TENANT'),
  ('residency.grant',   'Habiliter un opérateur sur une juridiction.',              'PLATFORM'),
  ('residency.revoke',  'Retirer une juridiction à un opérateur.',                  'PLATFORM')
ON CONFLICT (code) DO NOTHING;


CREATE TABLE admin.residency_region (
    code          text        NOT NULL,
    description   text        NOT NULL,
    jurisdiction  text        NOT NULL,
    declared_at   timestamptz NOT NULL DEFAULT now(),
    deprecated_at timestamptz,

    CONSTRAINT residency_region_pk PRIMARY KEY (code),
    CONSTRAINT residency_region_code_shape CHECK (code ~ '^[A-Z][A-Z0-9_]{1,15}$')
);

COMMENT ON TABLE admin.residency_region IS
'Les juridictions où la plateforme opère. Un VOCABULAIRE, pas une topologie :
la région dit sous quel droit vivent les données, jamais sur quelle machine.

Séparer les deux permet de déplacer une instance sans rien dire de faux, et de
tenir deux régions sur un même serveur tant que le cloisonnement logique suffit
— puis de les séparer physiquement sans changer une ligne de ce schéma.';

COMMENT ON COLUMN admin.residency_region.jurisdiction IS
'Le droit applicable, en clair. C''est ce qu''un juriste lit ; le code, c''est
ce que la machine compare.';

INSERT INTO admin.residency_region (code, description, jurisdiction) VALUES
  ('EU', 'Union européenne', 'RGPD — règlement (UE) 2016/679'),
  ('UK', 'Royaume-Uni',      'UK GDPR / Data Protection Act 2018'),
  ('CH', 'Suisse',           'nLPD / LPD révisée'),
  ('US', 'États-Unis',       'Lois d''État, droit fédéral sectoriel'),
  ('CA', 'Canada',           'LPRPDE et lois provinciales');

CREATE TRIGGER residency_region_no_delete
    BEFORE DELETE ON admin.residency_region
    FOR EACH ROW EXECUTE FUNCTION admin.no_delete();


CREATE TABLE admin.tenant_residency (
    tenant_id   uuid        NOT NULL,
    region_code text        NOT NULL,
    declared_at timestamptz NOT NULL DEFAULT now(),
    declared_by uuid        NOT NULL,
    command_id  uuid        NOT NULL,

    CONSTRAINT tenant_residency_pk PRIMARY KEY (tenant_id),
    CONSTRAINT tenant_residency_region_fk
        FOREIGN KEY (region_code) REFERENCES admin.residency_region (code)
        ON DELETE RESTRICT,
    CONSTRAINT tenant_residency_declared_by_fk
        FOREIGN KEY (declared_by) REFERENCES admin."user" (id) ON DELETE RESTRICT,
    CONSTRAINT tenant_residency_command_fk
        FOREIGN KEY (command_id) REFERENCES admin.signed_command (id)
        ON DELETE RESTRICT
);

COMMENT ON TABLE admin.tenant_residency IS
'Sous quelle juridiction vivent les données d''un client. Une ligne par client,
et elle ne bouge pas (AD102).

`tenant_id` est OPAQUE, comme partout dans cette base : aucune clé étrangère
vers `auth`, qui vit sur un autre serveur.';


CREATE TABLE admin.operator_residency (
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id     uuid        NOT NULL,
    region_code text        NOT NULL,
    reason      text        NOT NULL,

    granted_at  timestamptz NOT NULL DEFAULT now(),
    granted_by  uuid        NOT NULL,
    command_id  uuid        NOT NULL,

    revoked_at  timestamptz,
    revoked_by  uuid,
    revoked_command_id uuid,

    CONSTRAINT operator_residency_pk PRIMARY KEY (id),
    CONSTRAINT operator_residency_region_fk
        FOREIGN KEY (region_code) REFERENCES admin.residency_region (code)
        ON DELETE RESTRICT,
    CONSTRAINT operator_residency_user_fk
        FOREIGN KEY (user_id) REFERENCES admin."user" (id) ON DELETE RESTRICT,
    CONSTRAINT operator_residency_granted_by_fk
        FOREIGN KEY (granted_by) REFERENCES admin."user" (id) ON DELETE RESTRICT,
    CONSTRAINT operator_residency_revoked_by_fk
        FOREIGN KEY (revoked_by) REFERENCES admin."user" (id) ON DELETE RESTRICT,
    CONSTRAINT operator_residency_command_fk
        FOREIGN KEY (command_id) REFERENCES admin.signed_command (id)
        ON DELETE RESTRICT,
    CONSTRAINT operator_residency_revoked_command_fk
        FOREIGN KEY (revoked_command_id) REFERENCES admin.signed_command (id)
        ON DELETE RESTRICT,

    CONSTRAINT operator_residency_revocation_complete CHECK (
        (revoked_at IS NULL) = (revoked_by IS NULL)),
    CONSTRAINT operator_residency_not_for_oneself CHECK (
        granted_by <> user_id),
    CONSTRAINT operator_residency_reason_not_blank CHECK (btrim(reason) <> '')
);

CREATE UNIQUE INDEX operator_residency_live_uq
    ON admin.operator_residency (user_id, region_code) WHERE revoked_at IS NULL;
CREATE INDEX operator_residency_user_ix
    ON admin.operator_residency (user_id) WHERE revoked_at IS NULL;

COMMENT ON TABLE admin.operator_residency IS
'Quelles juridictions un opérateur a le droit d''ouvrir.

SECOND VERROU, et c''est tout l''intérêt : il ne dépend pas de l''autorité. Une
portée accordée par erreur — ou légitimement, puis devenue inappropriée — ne
suffit plus. Il faut les deux, accordés par des chemins différents, souvent par
des gens différents.

C''est la réponse à « votre support peut-il lire les données de notre filiale
allemande ». Elle cesse d''être une clause de contrat pour devenir une ligne
qu''on montre — ou dont on montre l''absence.

Jamais supprimée : on révoque (AD103). « Qui pouvait ouvrir l''Allemagne le
3 mars » doit rester une question à réponse.';


-- --- Les faits ne se réécrivent pas, et ils se signent ----------------

CREATE FUNCTION admin.residency_is_signed() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
AS $$
DECLARE
    v_command uuid;
    v_signer  uuid;
    v_action  text;
    v_scope   text := TG_ARGV[0];
    v_tenant  uuid;
BEGIN
    IF TG_ARGV[1] = 'REVOKE' THEN
        IF NEW.revoked_at IS NULL OR OLD.revoked_at IS NOT NULL THEN
            RETURN NEW;
        END IF;
        -- Sans auteur, `revocation_complete` dit mieux la même chose.
        IF NEW.revoked_by IS NULL THEN
            RETURN NEW;
        END IF;
        v_command := NEW.revoked_command_id;
        v_signer  := NEW.revoked_by;
        v_action  := 'residency.revoke';
    ELSIF v_scope = 'TENANT' THEN
        v_command := NEW.command_id;
        v_signer  := NEW.declared_by;
        v_action  := 'residency.declare';
        v_tenant  := NEW.tenant_id;
    ELSE
        v_command := NEW.command_id;
        v_signer  := NEW.granted_by;
        v_action  := 'residency.grant';
    END IF;

    -- LES QUATRE MÊMES ÉGALITÉS QU'AILLEURS. Sans la dernière, un
    -- administrateur signe et un autre se sert.
    PERFORM FROM admin.signed_command c
     WHERE c.id = v_command
       AND c.action = v_action
       AND c.scope = v_scope
       AND c.target_tenant_id IS NOT DISTINCT FROM v_tenant
       AND c.user_id = v_signer;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'the command spent is not a % by %', v_action, v_signer
            USING ERRCODE = 'AD101',
                  HINT = 'Declaring where a client''s data lives, and who may '
                         'open a jurisdiction, are claims that bind. They are '
                         'signed like every other heavy act.';
    END IF;

    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION admin.residency_is_signed() FROM PUBLIC;


CREATE FUNCTION admin.tenant_residency_is_a_fact() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'a tenant''s residency is a fact, not a setting'
        USING ERRCODE = 'AD102',
              HINT = 'Moving a client from one jurisdiction to another is an '
                     'export, a consent, sometimes a notification to a '
                     'supervisory authority. It is a project, not an UPDATE.';
END;
$$;

REVOKE EXECUTE ON FUNCTION admin.tenant_residency_is_a_fact() FROM PUBLIC;


CREATE FUNCTION admin.operator_residency_revocation_only() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'this residency is already revoked'
            USING ERRCODE = 'AD103';
    END IF;
    IF NEW.user_id     IS DISTINCT FROM OLD.user_id
    OR NEW.region_code IS DISTINCT FROM OLD.region_code
    OR NEW.granted_at  IS DISTINCT FROM OLD.granted_at
    OR NEW.granted_by  IS DISTINCT FROM OLD.granted_by
    OR NEW.command_id  IS DISTINCT FROM OLD.command_id
    OR NEW.reason      IS DISTINCT FROM OLD.reason THEN
        RAISE EXCEPTION 'only the revocation may be written, and only once'
            USING ERRCODE = 'AD103';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION admin.operator_residency_revocation_only() FROM PUBLIC;

CREATE TRIGGER tenant_residency_is_signed
    BEFORE INSERT ON admin.tenant_residency
    FOR EACH ROW EXECUTE FUNCTION admin.residency_is_signed('TENANT', 'GRANT');
CREATE TRIGGER tenant_residency_is_a_fact
    BEFORE UPDATE ON admin.tenant_residency
    FOR EACH ROW EXECUTE FUNCTION admin.tenant_residency_is_a_fact();
CREATE TRIGGER tenant_residency_no_delete
    BEFORE DELETE ON admin.tenant_residency
    FOR EACH ROW EXECUTE FUNCTION admin.no_delete();

CREATE TRIGGER operator_residency_is_signed
    BEFORE INSERT ON admin.operator_residency
    FOR EACH ROW EXECUTE FUNCTION admin.residency_is_signed('PLATFORM', 'GRANT');
CREATE TRIGGER operator_residency_revocation_is_signed
    BEFORE UPDATE ON admin.operator_residency
    FOR EACH ROW EXECUTE FUNCTION admin.residency_is_signed('PLATFORM', 'REVOKE');
CREATE TRIGGER operator_residency_revocation_only
    BEFORE UPDATE ON admin.operator_residency
    FOR EACH ROW EXECUTE FUNCTION admin.operator_residency_revocation_only();
CREATE TRIGGER operator_residency_no_delete
    BEFORE DELETE ON admin.operator_residency
    FOR EACH ROW EXECUTE FUNCTION admin.no_delete();


-- =====================================================================
--  3. LA DÉCISION
--
--  Une fonction, appelée par toutes les politiques. Un seul endroit à lire
--  pour savoir ce que la base autorise, un seul à corriger si elle a tort.
-- =====================================================================

CREATE FUNCTION admin.may_reside(p_user uuid, p_tenant uuid) RETURNS boolean
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO ''
AS $$
DECLARE
    v_region text;
BEGIN
    -- Une action sans client cible est une action de plateforme : aucune
    -- juridiction n'est ouverte, il n'y a rien à cloisonner.
    IF p_tenant IS NULL THEN
        RETURN true;
    END IF;

    SELECT region_code INTO v_region
      FROM admin.tenant_residency WHERE tenant_id = p_tenant;

    -- LE DÉFAUT EST LE REFUS. Un client provisionné sans résidence déclarée
    -- n'est pas ouvert à tout le monde en attendant : il est fermé jusqu'à ce
    -- que quelqu'un déclare sous quel droit il vit.
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    RETURN EXISTS (
        SELECT FROM admin.operator_residency r
         WHERE r.user_id = p_user
           AND r.region_code = v_region
           AND r.revoked_at IS NULL);
END;
$$;

COMMENT ON FUNCTION admin.may_reside(uuid, uuid) IS
'Cet opérateur peut-il ouvrir la juridiction de ce client ?

Indépendant de l''autorité, et vérifié avant elle : un refus de juridiction ne
dit pas si la portée existait.';


CREATE FUNCTION admin.is_platform_admin() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO ''
AS $$
    SELECT EXISTS (
        SELECT FROM admin.platform_admin p
         WHERE p.user_id = admin.app_admin()
           AND p.revoked_at IS NULL
           AND (p.expires_at IS NULL OR now() < p.expires_at));
$$;

COMMENT ON FUNCTION admin.is_platform_admin() IS
'Sans argument, et c''est voulu : la question porte sur l''opérateur de la
transaction, jamais sur un uuid qu''un appelant aurait choisi.';


CREATE FUNCTION admin.may_read(p_tenant uuid) RETURNS boolean
    LANGUAGE sql STABLE
    SET search_path TO ''
AS $$
    SELECT admin.may_reside(admin.app_admin(), p_tenant)
       AND admin.may_operate(admin.app_admin(), p_tenant);
$$;

COMMENT ON FUNCTION admin.may_read(uuid) IS
'LA question, posée par toutes les politiques de lecture. Deux verrous, dans
cet ordre : la juridiction d''abord, l''autorité ensuite. Il faut les deux, et
aucun octroi d''autorité n''ouvre une juridiction.';

-- Postgres accorde EXECUTE à PUBLIC sur toute fonction créée, et trois de
-- celles-ci sont DEFINER : sans ces lignes, n'importe quel rôle du cluster
-- interrogerait l'autorité d'administration avec les droits du propriétaire.
REVOKE EXECUTE ON FUNCTION admin.app_admin()            FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION admin.may_reside(uuid, uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION admin.may_read(uuid)         FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION admin.is_platform_admin()    FROM PUBLIC;

GRANT EXECUTE ON FUNCTION admin.app_admin()            TO app_admin_plane;
GRANT EXECUTE ON FUNCTION admin.may_reside(uuid, uuid) TO app_admin_plane;
GRANT EXECUTE ON FUNCTION admin.may_read(uuid)         TO app_admin_plane;
GRANT EXECUTE ON FUNCTION admin.is_platform_admin()    TO app_admin_plane;


-- =====================================================================
--  4. LES FRONTIÈRES
--
--  Deux axes, deux règles.
--
--  L'AXE CLIENT — les tables qui parlent d'un client : on voit celles des
--  clients qu'on peut lire.
--
--  L'AXE OPÉRATEUR — sessions, jetons, clés, défis : rien de tout cela ne
--  porte de client, et pourtant tout y mène. La session d'un opérateur dit
--  quand il travaille ; ses clés, ce qu'il a pu signer. On voit les siennes,
--  et un administrateur de plateforme voit tout.
-- =====================================================================

DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('admin','admin_tenant'), ('admin','impersonation'),
        ('admin','signed_command'), ('admin','authority_request'),
        ('admin','tenant_residency'), ('admin','operator_residency'),
        ('admin','session'), ('admin','token_pair'), ('admin','identity'),
        ('akeys','key'), ('webauthn','authenticator'), ('webauthn','challenge')
    ) AS t(s, n) LOOP
        EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', r.s, r.n);
        EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY',  r.s, r.n);
        -- LE CHEMIN DE CONFIANCE, RENDU VISIBLE. Voir l'entête : sans lui les
        -- fonctions DEFINER deviennent aveugles et plus personne ne se
        -- connecte. Une politique par table plutôt qu'un privilège global,
        -- pour qu'un auditeur lise la liste au lieu de la deviner.
        EXECUTE format(
            'CREATE POLICY owner_is_the_vetted_path ON %I.%I '
            'FOR ALL TO admin_owner USING (true) WITH CHECK (true)', r.s, r.n);
    END LOOP;
END $$;

-- =====================================================================
--  LE PRIX DE `security_invoker`, ET POURQUOI ON LE PAIE
--
--  Une vue de `api` s'execute avec les droits de SON APPELANT. C'est ce qui
--  la fait tomber sous `own_or_platform` ou `tenant_visible` plutot que sous
--  `owner_is_the_vetted_path` — donc ce qui la filtre.
--
--  Mais lire par une vue en `security_invoker` exige le privilege sur la
--  TABLE aussi, pas seulement sur la vue. Sans ces GRANT, l'appelant se voit
--  repondre « permission denied for table session » : la fuite devient un
--  refus, ce qui est mieux, mais la vue ne sert plus a rien.
--
--  CE QUE CES GRANT N'ELARGISSENT PAS. Chacune de ces vues expose DEJA toutes
--  les colonnes de sa table — sept sur sept, dix sur dix. Le privilege de
--  table ne montre donc rien que la vue ne montrait pas, et les politiques
--  continuent de trancher ligne par ligne.
--
--  Les privileges sont ceux, exactement, que le role detient sur la vue
--  correspondante. Ni plus, ni moins.
-- =====================================================================

GRANT INSERT, SELECT ON admin.identity TO app_admin_plane;
GRANT UPDATE (provider_id, provision_key) ON admin.identity TO app_admin_plane;

GRANT INSERT, SELECT ON admin.session TO app_admin_plane;
GRANT UPDATE (cnf_jkt, end_reason, ended_at) ON admin.session TO app_admin_plane;

GRANT INSERT, SELECT ON admin.token_pair TO app_admin_plane;

GRANT INSERT, SELECT ON admin.operator_residency TO app_admin_plane;
GRANT UPDATE (revoked_at, revoked_by, revoked_command_id)
  ON admin.operator_residency TO app_admin_plane;

GRANT INSERT, SELECT ON admin.tenant_residency TO app_admin_plane;

GRANT INSERT, SELECT ON webauthn.authenticator TO app_admin_plane;
GRANT UPDATE (revoked_at) ON webauthn.authenticator TO app_admin_plane;

GRANT DELETE, SELECT ON webauthn.challenge TO app_admin_plane;
GRANT INSERT (action, challenge, expires_at, scope, session_id, target_tenant_id, user_id)
  ON webauthn.challenge TO app_admin_plane;

-- --- L'axe client -----------------------------------------------------

CREATE POLICY tenant_visible ON admin.admin_tenant
    FOR ALL TO app_admin_plane
    USING (admin.may_read(tenant_id)) WITH CHECK (admin.may_read(tenant_id));

CREATE POLICY tenant_visible ON admin.authority_request
    FOR ALL TO app_admin_plane
    USING (admin.may_read(tenant_id)) WITH CHECK (admin.may_read(tenant_id));

CREATE POLICY tenant_visible ON admin.tenant_residency
    FOR ALL TO app_admin_plane
    USING (admin.may_read(tenant_id)) WITH CHECK (admin.may_read(tenant_id));

CREATE POLICY tenant_visible ON admin.impersonation
    FOR ALL TO app_admin_plane
    USING (admin.may_read(target_tenant_id))
    WITH CHECK (admin.may_read(target_tenant_id));

CREATE POLICY tenant_visible ON admin.signed_command
    FOR ALL TO app_admin_plane
    USING (admin.may_read(target_tenant_id))
    WITH CHECK (admin.may_read(target_tenant_id));

COMMENT ON POLICY tenant_visible ON admin.signed_command IS
'Les commandes de plateforme (`target_tenant_id` NULL) ne sont visibles que des
administrateurs de PLATEFORME, et c''est voulu.

`may_reside` rend vrai sur une cible nulle — aucune juridiction n''est ouverte,
il n''y a rien à cloisonner. Mais `may_operate(user, NULL)` n''est vrai que pour
un admin global : « une action sans client cible est par définition une action
de plateforme ». Un administrateur chez un client ne voit donc pas ce que
l''éditeur fait de son côté, ce qui est la bonne réponse — ce ne sont pas ses
affaires, et l''inverse lui apprendrait la liste des autres clients.';

-- --- L'axe opérateur --------------------------------------------------

CREATE POLICY own_or_platform ON admin.session
    FOR ALL TO app_admin_plane
    USING (user_id = admin.app_admin() OR admin.is_platform_admin())
    WITH CHECK (user_id = admin.app_admin() OR admin.is_platform_admin());

CREATE POLICY own_or_platform ON admin.identity
    FOR ALL TO app_admin_plane
    USING (user_id = admin.app_admin() OR admin.is_platform_admin())
    WITH CHECK (user_id = admin.app_admin() OR admin.is_platform_admin());

CREATE POLICY own_or_platform ON akeys.key
    FOR ALL TO app_admin_plane
    USING (user_id = admin.app_admin() OR admin.is_platform_admin())
    WITH CHECK (user_id = admin.app_admin() OR admin.is_platform_admin());

CREATE POLICY own_or_platform ON webauthn.authenticator
    FOR ALL TO app_admin_plane
    USING (user_id = admin.app_admin() OR admin.is_platform_admin())
    WITH CHECK (user_id = admin.app_admin() OR admin.is_platform_admin());

-- On lit sa propre résidence — savoir ce qu'on a le droit d'ouvrir n'est pas un
-- secret. On n'en écrit jamais : habiliter est une action de plateforme.
CREATE POLICY own_or_platform ON admin.operator_residency
    FOR ALL TO app_admin_plane
    USING (user_id = admin.app_admin() OR admin.is_platform_admin())
    WITH CHECK (admin.is_platform_admin());

-- La paire et le défi n'ont pas de `user_id` : ils passent par leur session.
CREATE POLICY own_or_platform ON admin.token_pair
    FOR ALL TO app_admin_plane
    USING (admin.is_platform_admin() OR EXISTS (
        SELECT FROM admin.session AS s
         WHERE s.id = token_pair.session_id AND s.user_id = admin.app_admin()))
    WITH CHECK (admin.is_platform_admin() OR EXISTS (
        SELECT FROM admin.session AS s
         WHERE s.id = token_pair.session_id AND s.user_id = admin.app_admin()));

CREATE POLICY own_or_platform ON webauthn.challenge
    FOR ALL TO app_admin_plane
    USING (admin.is_platform_admin() OR EXISTS (
        SELECT FROM admin.session AS s
         WHERE s.id = challenge.session_id AND s.user_id = admin.app_admin()))
    WITH CHECK (admin.is_platform_admin() OR EXISTS (
        SELECT FROM admin.session AS s
         WHERE s.id = challenge.session_id AND s.user_id = admin.app_admin()));


-- =====================================================================
--  5. CE QUE L'ON MONTRE
-- =====================================================================

CREATE VIEW admin.residency_map WITH (security_invoker = TRUE) AS
SELECT r.code AS region,
       r.jurisdiction,
       count(DISTINCT t.tenant_id) AS tenants,
       count(DISTINCT o.user_id) FILTER (WHERE o.revoked_at IS NULL) AS operators
  FROM admin.residency_region AS r
  LEFT JOIN admin.tenant_residency   AS t ON r.code = t.region_code
  LEFT JOIN admin.operator_residency AS o ON r.code = o.region_code
 WHERE r.deprecated_at IS NULL
 GROUP BY r.code, r.jurisdiction;

COMMENT ON VIEW admin.residency_map IS
'« Qui peut ouvrir quoi, et où », en une lecture. C''est la première chose que
demande un audit de grand groupe, et la première qu''on ne sait jamais montrer.';


CREATE VIEW admin.tenant_without_residency WITH (security_invoker = TRUE) AS
SELECT t.tenant_id, min(t.granted_at) AS first_scoped_at
  FROM admin.admin_tenant AS t
  LEFT JOIN admin.tenant_residency AS r ON t.tenant_id = r.tenant_id
 WHERE r.tenant_id IS NULL
 GROUP BY t.tenant_id;

COMMENT ON VIEW admin.tenant_without_residency IS
'Les clients qu''aucun opérateur ne peut atteindre, faute de juridiction
déclarée. Le défaut de `may_reside` étant le refus, cette vue liste des accès
CASSÉS, pas des accès trop larges — l''erreur du bon côté, et la liste qu''on
regarde après chaque provisionnement.

`security_invoker` : elle ne montre que ce que l''appelant peut déjà voir. Un
opérateur n''y découvre pas l''existence de clients hors de sa portée.';


-- =====================================================================
--  6. LES DROITS
-- =====================================================================

CREATE VIEW api.residency_region AS
  SELECT code, description, jurisdiction, deprecated_at
    FROM admin.residency_region;
CREATE VIEW api.tenant_residency
    WITH (security_invoker = TRUE)
AS
  SELECT tenant_id, region_code, declared_at, declared_by, command_id
    FROM admin.tenant_residency;
CREATE VIEW api.operator_residency
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, region_code, reason, granted_at, granted_by, command_id,
         revoked_at, revoked_by, revoked_command_id
    FROM admin.operator_residency;
CREATE VIEW api.residency_map
    WITH (security_invoker = TRUE)
AS
  SELECT region, jurisdiction, tenants, operators
    FROM admin.residency_map;
CREATE VIEW api.tenant_without_residency
    WITH (security_invoker = TRUE)
AS
  SELECT tenant_id, first_scoped_at
    FROM admin.tenant_without_residency;

GRANT SELECT ON api.residency_region, api.residency_map,
                api.tenant_without_residency TO app_admin_plane;
GRANT SELECT, INSERT ON api.tenant_residency, api.operator_residency
    TO app_admin_plane;
GRANT UPDATE (revoked_at, revoked_by, revoked_command_id)
    ON api.operator_residency TO app_admin_plane;

GRANT SELECT ON admin.residency_region TO admin_auditor;
GRANT SELECT ON admin.residency_map    TO admin_auditor;

SELECT audit.watch('admin', 'tenant_residency',
       '{tenant_id, region_code, declared_at, declared_by, command_id}');
SELECT audit.watch('admin', 'operator_residency',
       '{id, user_id, region_code, reason, granted_at, granted_by, command_id,
         revoked_at, revoked_by, revoked_command_id}');
SELECT audit.watch('admin', 'residency_region',
       '{code, description, jurisdiction, declared_at, deprecated_at}');

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DELETE FROM audit.auditable_column
 WHERE schema_name = 'admin'
   AND table_name IN ('tenant_residency', 'operator_residency', 'residency_region');
DELETE FROM audit.watched
 WHERE schema_name = 'admin'
   AND table_name IN ('tenant_residency', 'operator_residency', 'residency_region');

DROP VIEW api.tenant_without_residency;
DROP VIEW api.residency_map;
DROP VIEW api.operator_residency;
DROP VIEW api.tenant_residency;
DROP VIEW api.residency_region;
DROP VIEW admin.tenant_without_residency;
DROP VIEW admin.residency_map;

-- Les privileges de table qu'exige `security_invoker` — voir la montee.
REVOKE ALL ON admin.identity, admin.session, admin.token_pair,
              admin.operator_residency, admin.tenant_residency,
              webauthn.authenticator, webauthn.challenge
  FROM app_admin_plane;

DROP POLICY own_or_platform ON webauthn.challenge;
DROP POLICY own_or_platform ON admin.token_pair;
DROP POLICY own_or_platform ON admin.operator_residency;
DROP POLICY own_or_platform ON webauthn.authenticator;
DROP POLICY own_or_platform ON akeys.key;
DROP POLICY own_or_platform ON admin.identity;
DROP POLICY own_or_platform ON admin.session;
DROP POLICY tenant_visible ON admin.signed_command;
DROP POLICY tenant_visible ON admin.impersonation;
DROP POLICY tenant_visible ON admin.tenant_residency;
DROP POLICY tenant_visible ON admin.authority_request;
DROP POLICY tenant_visible ON admin.admin_tenant;

DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('admin','admin_tenant'), ('admin','impersonation'),
        ('admin','signed_command'), ('admin','authority_request'),
        ('admin','tenant_residency'), ('admin','operator_residency'),
        ('admin','session'), ('admin','token_pair'), ('admin','identity'),
        ('akeys','key'), ('webauthn','authenticator'), ('webauthn','challenge')
    ) AS t(s, n) LOOP
        EXECUTE format('DROP POLICY owner_is_the_vetted_path ON %I.%I', r.s, r.n);
        EXECUTE format('ALTER TABLE %I.%I NO FORCE ROW LEVEL SECURITY', r.s, r.n);
        EXECUTE format('ALTER TABLE %I.%I DISABLE ROW LEVEL SECURITY', r.s, r.n);
    END LOOP;
END $$;

DROP FUNCTION admin.may_read(uuid);
DROP FUNCTION admin.is_platform_admin();
DROP FUNCTION admin.may_reside(uuid, uuid);

DROP TRIGGER operator_residency_no_delete           ON admin.operator_residency;
DROP TRIGGER operator_residency_revocation_only     ON admin.operator_residency;
DROP TRIGGER operator_residency_revocation_is_signed ON admin.operator_residency;
DROP TRIGGER operator_residency_is_signed           ON admin.operator_residency;
DROP TRIGGER tenant_residency_no_delete             ON admin.tenant_residency;
DROP TRIGGER tenant_residency_is_a_fact             ON admin.tenant_residency;
DROP TRIGGER tenant_residency_is_signed             ON admin.tenant_residency;
DROP TRIGGER residency_region_no_delete             ON admin.residency_region;

DROP FUNCTION admin.operator_residency_revocation_only();
DROP FUNCTION admin.tenant_residency_is_a_fact();
DROP FUNCTION admin.residency_is_signed();

DROP TABLE admin.operator_residency;
DROP TABLE admin.tenant_residency;
DROP TABLE admin.residency_region;

DROP FUNCTION admin.app_admin();

ALTER TABLE admin.command_action DISABLE TRIGGER command_action_no_delete;
DELETE FROM admin.command_action c
 WHERE c.code IN ('residency.declare', 'residency.grant', 'residency.revoke')
   AND NOT EXISTS (SELECT FROM webauthn.challenge AS x WHERE x.action = c.code)
   AND NOT EXISTS (SELECT FROM admin.signed_command AS x WHERE x.action = c.code);
ALTER TABLE admin.command_action ENABLE TRIGGER command_action_no_delete;

RESET ROLE;
