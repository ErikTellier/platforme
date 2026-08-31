-- Up Migration

-- LA POLITIQUE APPELAIT `app_admin()` DEUX FOIS PAR LIGNE.
--
--     SELECT admin.may_reside(admin.app_admin(), p_tenant)
--        AND admin.may_operate(admin.app_admin(), p_tenant);
--
-- Deux fois la même question, sur la même transaction, dont la réponse ne peut
-- pas avoir changé entre les deux. Mesuré sur cinquante mille lignes portant
-- TOUTES le même client :
--
--     may_read     50 000 appels    447 ms
--     app_admin   100 000 appels     51 ms      ← deux par ligne
--
--
-- ═══ CE QUE LA MESURE A DÉMENTI ═══
--
-- On m'a dit que Postgres met en cache les fonctions STABLE dans une même
-- requête pour des arguments identiques, donc qu'un balayage sur un client
-- unique ne paierait qu'une fois. C'est faux, et le chiffre ci-dessus le dit :
-- cinquante mille lignes, un seul `tenant_id`, cinquante mille appels.
--
-- `STABLE` garantit que la fonction ne CHANGERA PAS d'avis pendant
-- l'instruction. Elle n'autorise pas Postgres à mémoriser son résultat par
-- valeur d'argument, et il ne le fait pas. La différence compte : elle
-- transforme « on ne paie qu'une fois par client » en « on paie par ligne,
-- toujours ».
--
--
-- ═══ CE QUI RESTE VRAI, ET QU'ON GARDE ═══
--
-- L'ordre. La résidence est vérifiée AVANT l'autorité, pour ne pas révéler si
-- une portée existait — et ça se paie en performance AUSSI : quand la
-- juridiction refuse, `may_operate` n'est jamais appelée. Mesuré sur le même
-- jeu, ligne invisible : 144 ms au lieu de 447. Le court-circuit est explicite
-- ici plutôt que confié à l'ordre d'évaluation d'un `AND`, que Postgres ne
-- garantit pas.
--
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE OR REPLACE FUNCTION admin.may_read(p_tenant uuid)
RETURNS boolean
LANGUAGE plpgsql STABLE
SET search_path TO ''
AS $$
DECLARE
    who uuid := admin.app_admin();
BEGIN
    -- La juridiction d'abord : un refus de résidence ne dit pas si la portée
    -- existait, et il évite l'appel suivant.
    IF NOT admin.may_reside(who, p_tenant) THEN
        RETURN false;
    END IF;
    RETURN admin.may_operate(who, p_tenant);
END;
$$;

COMMENT ON FUNCTION admin.may_read(uuid) IS
'LA question, posée par toutes les politiques de lecture. Deux verrous, dans
cet ordre : la juridiction d''abord, l''autorité ensuite. Il faut les deux, et
aucun octroi d''autorité n''ouvre une juridiction.

L''opérateur est demandé UNE fois. La version précédente appelait `app_admin()`
dans chaque branche — deux fois par ligne, cent mille fois sur un balayage de
cinquante mille. Et le court-circuit est écrit plutôt que confié à l''ordre
d''évaluation d''un `AND`, que Postgres ne garantit pas.';

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

CREATE OR REPLACE FUNCTION admin.may_read(p_tenant uuid)
RETURNS boolean
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

RESET ROLE;
