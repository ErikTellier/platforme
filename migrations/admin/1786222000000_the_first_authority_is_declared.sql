-- Up Migration

-- LE TROISIÈME CERCLE, ET LE DERNIER.
--
-- Deux ont déjà été rompus, chacun par sa migration :
--
--   l'identité   `the_first_admin_is_declared` — personne n'entre tant que
--                personne n'est déclaré, et rien ne déclare le premier.
--   la clé       `the_first_key_needs_a_ticket` — on n'entre pas sans toucher sa
--                clé, on n'enregistre pas sa clé sans être entré.
--
-- Voici le troisième. `verify_presence` exige `may_operate`, donc une autorité.
-- Or `platform_admin` exige une commande signée, un signataire ayant autorité et
-- une demande approuvée — c'est-à-dire une présence, donc une autorité.
--
-- Le schéma avait déjà prévu la sortie : `authority_is_signed`,
-- `grant_follows_a_request` et `signer_has_authority` portent tous les trois la
-- même exemption — `NOT EXISTS (SELECT FROM admin.platform_admin)`. Sans filtre
-- sur `revoked_at`, donc valable UNE FOIS dans la vie de la base : révoquer tout
-- ne rouvre pas la porte. Ce qui manquait n'était pas le mécanisme, c'était
-- quelqu'un pour s'en servir.
--
--
-- ═══ AD074 NE SE RELÂCHE NULLE PART, ET C'EST VOULU ═══
--
--     IF NEW.granted_by = NEW.user_id THEN
--         RAISE EXCEPTION 'authority is never granted to oneself'
--
-- Aucune exemption d'amorçage, contrairement aux trois autres gardes. La règle
-- ne dit pas « deux humains dès que possible », elle dit « jamais soi-même », et
-- la première autorité n'y échappe pas.
--
-- Il faut donc un octroyeur DISTINCT. Et à l'amorçage, il n'existe personne.
--
--
-- ═══ L'OCTROYEUR EST UNE DÉCLARATION, PAS UNE PERSONNE ═══
--
-- On pourrait exiger un second compte au fournisseur d'identité. Ce serait plus
-- pur, et ce serait faux : ce second compte ne pourrait rien faire d'autre que
-- cet unique octroi, puisque lui aussi serait sans autorité. On aurait déplacé
-- le cercle d'un cran en croyant l'avoir rompu.
--
-- L'octroyeur est donc un `admin."user"` SANS IDENTITÉ, et désactivé dans le même
-- geste. Les deux propriétés se cumulent :
--
--   · sans identité, `ResolveAdminByOID` ne peut jamais le résoudre — la
--     jointure sur `identity` ne rend rien, quel que soit l'oid présenté ;
--   · désactivé, `session_emission_guard` refuserait de toute façon (AD001).
--
-- Il ne peut donc pas agir, pas une seule fois, pas même le jour de sa création.
-- Son unique trace est le `granted_by` de cette ligne — et c'est le but : l'audit
-- doit pouvoir dire qui a accordé la première autorité, et la réponse honnête est
-- « l'amorçage », pas un humain qu'on aurait inventé pour la forme.
--
--
-- ═══ BRIS DE GLACE, PARCE QUE C'EN EST UN ═══
--
-- `PLATFORM` exige un second approbateur distinct (AD075). À l'amorçage il n'y a
-- ni premier ni second, donc la cérémonie n'existe pas encore.
--
-- `break_glass` sort avant ce contrôle, et la politique de portée l'autorise
-- explicitement pour `PLATFORM` (`allows_break_glass`). Ce n'est pas un
-- contournement : c'est exactement ce que le bris de glace nomme — un acte
-- légitime hors de la cérémonie ordinaire, qui doit rester VISIBLE. Cette ligne
-- apparaîtra dans `admin.break_glass_use` pour toujours, et c'est bien.
--
--
-- ═══ CE QU'IL FAUDRA FAIRE QUAND UN SECOND ADMINISTRATEUR EXISTERA ═══
--
-- Rien n'oblige à en rester là. Le jour où un second compte réel est déclaré et
-- lié, le parcours normal reprend ses droits : demande, approbation par un
-- second regard, présence prouvée, commande signée. Cette autorité d'amorçage
-- peut alors être révoquée et remplacée par une autre, accordée dans les règles.
--
-- Le quatre-yeux n'est pas abandonné, il est différé — et la ligne de bris de
-- glace dit exactement de combien.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. Si une autorité plateforme existe déjà, la migration ne
--   fait rien : elle n'a de sens qu'une fois, et les exemptions qu'elle utilise
--   se sont fermées d'elles-mêmes.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

DO $$
DECLARE
  v_oid    text := nullif(current_setting('app.bootstrap_admin_oid', true), '');
  v_admin  uuid;
  v_source uuid;
BEGIN
  -- Une autorité plateforme existe déjà : il n'y a plus de cercle à rompre, et
  -- les exemptions sur lesquelles cette migration s'appuie sont refermées.
  IF EXISTS (SELECT FROM admin.platform_admin) THEN
    RAISE NOTICE 'une autorité plateforme existe déjà — rien à déclarer';
    RETURN;
  END IF;

  IF v_oid IS NULL THEN
    RAISE EXCEPTION 'aucun oid d''amorçage'
      USING HINT = 'Poser BOOTSTRAP_ADMIN_OID : c''est le compte qui reçoit la première autorité de plateforme.';
  END IF;

  SELECT u.id INTO v_admin
    FROM admin."user" u
    JOIN admin.identity i ON i.user_id = u.id AND i.provider = 'ENTRA'
   WHERE i.provider_id = v_oid
     AND u.deactivated_at IS NULL;

  IF v_admin IS NULL THEN
    RAISE EXCEPTION 'aucun administrateur actif ne porte l''oid %', v_oid
      USING HINT = 'the_first_admin_is_declared doit avoir tourné, et le compte doit s''être connecté une fois pour que son oid soit capturé.';
  END IF;

  -- L'OCTROYEUR. Sans identité, donc introuvable par ResolveAdminByOID ;
  -- désactivé, donc incapable d'ouvrir une session (AD001). Il existe pour
  -- porter un nom dans `granted_by`, et pour rien d'autre.
  INSERT INTO admin."user" (deactivated_at) VALUES (now())
  RETURNING id INTO v_source;

  INSERT INTO admin.platform_admin (user_id, granted_by, reason, break_glass)
  VALUES (
    v_admin, v_source,
    'Autorité d''amorçage : accordée par la migration, hors cérémonie, faute de '
    || 'second administrateur pour l''approuver. À remplacer par un octroi en '
    || 'règle dès qu''un second compte est déclaré et lié.',
    true
  );

  RAISE NOTICE 'autorité de plateforme accordée à % par l''amorçage %', v_admin, v_source;
END $$;

RESET ROLE;

-- Down Migration

--
-- ⚠ RIEN. Une autorité accordée est un FAIT, et `platform_admin` est en
-- append-only : elle se révoque, elle ne s'efface pas. Or révoquer ici serait
-- pire que ne rien faire — la rétrogradation d'une migration rendrait la
-- plateforme inadministrable, sans que personne ne l'ait décidé.
--
-- Si cette autorité doit tomber, elle tombe par le parcours de révocation, avec
-- ce qu'il exige : quelqu'un qui la révoque, et une trace de qui.

SELECT 1;
