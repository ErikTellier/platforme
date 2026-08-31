-- Up Migration

-- CE QUE CHAQUE RÉFÉRENCE OPAQUE DÉSIGNE.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

COMMENT ON COLUMN admin.impersonation.ticket_ref IS
'La référence du billet qui justifie l''accès. Du TEXTE et non un identifiant :
elle vaut aussi bien pour `ticket.ticket.reference` que pour un outil externe,
et un opérateur d''astreinte à trois heures du matin ne doit pas se voir
refuser une intervention parce que le suivi de demandes est en panne.';
COMMENT ON COLUMN akeys.key.kms_ref IS
'Hors plateforme : le service de gestion de clés. La base porte le chemin de
la clé privée, jamais la clé.';

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;
COMMENT ON COLUMN admin.impersonation.ticket_ref IS NULL;
COMMENT ON COLUMN akeys.key.kms_ref IS NULL;
RESET ROLE;
