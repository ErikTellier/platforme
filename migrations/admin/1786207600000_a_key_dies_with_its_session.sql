-- Up Migration

-- UNE CLÉ QUI SURVIT À LA DÉCONNEXION.
--
-- `akeys.key` est émise à la connexion et bornée par le plafond de sa session :
-- `signs_until` VAUT ce plafond, exactement, pour éviter la classe de bug des
-- « deux instants calculés à quelques millisecondes d'écart ». Juste.
--
-- Mais le plafond est une HORLOGE, et une déconnexion n'est pas une horloge.
-- Un administrateur qui ferme sa session à la dixième minute laisse derrière
-- lui une clé qui signe encore cinquante minutes :
--
--   · `akeys.signing_key` la publie toujours — la vue ne regarde que l'état,
--     la destruction du privé et `signs_until` ;
--   · et surtout la garde de `admin.signed_command` l'accepte : elle relit
--     `activated_at`, `private_destroyed_at` et `signs_until`, jamais
--     `session.ended_at`.
--
-- Donc une commande signée APRÈS la déconnexion passait. Ce qui vide de son
-- sens la seule chose que la session garantit : que quelqu'un était là.
--
-- Le cycle voulu est explicite — la clé est générée à la connexion et INVALIDE
-- À LA DÉCONNEXION. Deux endroits à corriger, et pas trois.
--
--
-- ═══ CE QU'ON NE TOUCHE PAS : LA VÉRIFICATION ═══
--
-- `akeys.verifiable_key` continue d'ignorer la fin de session, et c'est
-- délibéré. Signer et vérifier sont deux fenêtres différentes : une commande
-- légitimement signée à la dixième minute doit rester vérifiable après que son
-- auteur s'est déconnecté, sinon se déconnecter invaliderait rétroactivement
-- ce qu'on vient de faire. `published_until` garde sa grâce de dix minutes.
--
-- Même raison pour `destroyable_key` : ce qui décide qu'un privé peut être
-- détruit, c'est la fin de la fenêtre de VÉRIFICATION, pas celle de signature.
--
--
-- ═══ PAS DE CODE NOUVEAU ═══
--
-- `AD082` dit déjà « la clé ne pouvait pas signer à l'instant réclamé », et
-- une session fermée est précisément ce cas. Sa réaction documentée — relire
-- la clé vivante au lieu de réutiliser un `kid` en cache — reste la bonne.
-- Ajouter un code pour la même réaction ferait grossir l'API sans rien
-- apprendre à l'appelant.
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD082  the signing key may not sign at the moment claimed
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- La vue cesse de publier une clé dont la session est fermée. Les colonnes ne
-- changent pas, donc `CREATE OR REPLACE` suffit et les droits sont conservés.
CREATE OR REPLACE VIEW akeys.signing_key
    WITH (security_invoker = TRUE)
AS
  SELECT k.id, k.kid, k.user_id, k.session_id, k.state, k.public_jwk,
         k.created_at, k.activated_at, k.signs_until, k.published_until
    FROM akeys.key AS k
    INNER JOIN admin.session AS s ON k.session_id = s.id
   WHERE k.state = 'ACTIVE'
     AND k.private_destroyed_at IS NULL
     AND now() < k.signs_until
     AND s.ended_at IS NULL;

COMMENT ON VIEW akeys.signing_key IS
'Les clés qui peuvent signer MAINTENANT. Trois bornes et pas deux : la fenêtre
de signature, la destruction du privé, et la SESSION. Une clé dont la session
est fermée ne signe plus, même s''il lui restait cinquante minutes d''horloge —
une déconnexion n''est pas une horloge.';


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

    -- L'autorité est relue ICI aussi. verify_presence l'a déjà vérifiée à la
    -- consommation, mais une révocation peut tomber entre les deux — et c'est
    -- la commande qui produit l'effet, pas le défi.
    IF NOT admin.may_operate(NEW.user_id, NEW.target_tenant_id) THEN
        RAISE EXCEPTION 'admin % may not operate on %',
            NEW.user_id, coalesce(NEW.target_tenant_id::text, '(platform)')
            USING ERRCODE = 'AD080';
    END IF;

    -- LA SESSION, ET PAS SEULEMENT L'HORLOGE DE LA CLÉ. C'est l'ajout : une
    -- session close rend sa clé inutilisable à l'instant, sans attendre que
    -- `signs_until` la rattrape.
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

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

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

CREATE OR REPLACE VIEW akeys.signing_key
    WITH (security_invoker = TRUE)
AS
  SELECT id, kid, user_id, session_id, state, public_jwk,
         created_at, activated_at, signs_until, published_until
    FROM akeys.key
   WHERE state = 'ACTIVE'
     AND private_destroyed_at IS NULL
     AND now() < signs_until;

COMMENT ON VIEW akeys.signing_key IS
  'WHICH key an admin may currently sign with. At most one row per admin. Carries no kms_ref: observing rotation is not the same right as signing.';

RESET ROLE;
