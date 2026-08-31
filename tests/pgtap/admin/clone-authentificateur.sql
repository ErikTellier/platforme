-- LE CLONE SOUPÇONNÉ, ET CE QU'ON EN FAIT.
--
-- ═══ L'INVARIANT QUE CE FICHIER DÉFEND ═══
--
-- Le compteur d'un authentificateur WebAuthn progresse STRICTEMENT à chaque
-- assertion. C'est le seul signal que la norme offre contre la duplication d'une
-- clé matérielle : deux exemplaires du même secret comptent chacun de leur côté,
-- et l'un des deux finit par présenter un nombre que l'autre a déjà dépassé.
--
-- « Strictement » compte autant que « progresse ». Un compteur INCHANGÉ est un
-- signal aussi net qu'une régression : un authentificateur authentique
-- incrémente à chaque usage, donc un nombre identique veut dire que l'assertion
-- ne vient pas de lui. Une garde écrite `<` au lieu de `<=` laisserait passer
-- exactement le rejeu qu'on cherche à voir, et aucun test de catalogue ne ferait
-- la différence — c'est ce que ce banc attrape.
--
-- ═══ DÉTECTER NE SUFFIT PAS : `disarm_clone` ═══
--
-- La migration `a_suspected_clone_is_disarmed` raconte l'incident : le plan
-- détectait la régression, rendait 409, journalisait — et laissait la session
-- ouverte et l'accréditation vivante. Détecter une clé clonée et la laisser en
-- place est la même faute que la clé qui survit à sa session, prise par
-- l'autre bout.
--
-- `webauthn.disarm_clone()` fait les DEUX gestes dans le même acte : révoquer
-- l'accréditation, et fermer les sessions vivantes de son administrateur. Le
-- second n'est pas un supplément — un porteur en cours ne relit jamais les
-- authentificateurs, il ne connaît que sa paire, et entrerait donc par la porte
-- qu'on vient de condamner.
--
-- Et sous SON motif, `CLONED`. Un journal d'incident se lit des mois plus tard :
-- « clone soupçonné sur telle accréditation » n'est pas « quelqu'un a rejoué un
-- jeton ». Ce banc vérifie le motif, pas seulement la fermeture.
--
-- ═══ CE QUI EST DÉLIBÉRÉMENT PERMISSIF ═══
--
-- `disarm_clone` sur une accréditation inconnue, déjà désarmée, ou appartenant à
-- quelqu'un d'autre rend ZÉRO LIGNE sans se plaindre. Le chemin qui y mène est
-- un chemin d'incident, où l'on repasse deux fois. Deux assertions ci-dessous
-- portent là-dessus, et une troisième vérifie que « appartenant à quelqu'un
-- d'autre » ne veut pas dire « désarmé quand même ».
--
-- ═══ CE QUE CE BANC TUE, MESURÉ ═══
--
--   déclencheur   sign_count_guard
--   déclencheur   revocation_is_final
--   déclencheur   no_delete_authn
--   index         uq_authenticator_credential
--   fonction      webauthn.disarm_clone
--
-- LA DERNIÈRE A COÛTÉ UNE FAMILLE AU LANCEUR. La moitié de ce fichier éprouve
-- `disarm_clone()` — les six assertions qui vérifient que la session tombe, et
-- sous `CLONED` — et le mutant ne savait pas retirer une fonction : il lisait
-- « rien de tué » sur du code entièrement couvert. La famille `fonction`
-- existe maintenant, et ces six assertions comptent.
--
-- Le compte de la base vit dans `packages/harnais/mutation-sql.mjs`.
--
-- ═══ LE MONTAGE ═══
--
--   U  la victime : une accréditation, une session vivante
--   V  quelqu'un d'autre : une accréditation, que rien ne doit toucher
--
-- Aucun des deux n'a besoin d'autorité : enregistrer un authentificateur ne
-- passe par aucune commande signée. C'est le seul banc de ce dossier qui n'a pas
-- à monter la cérémonie complète.

SET search_path TO pgtap, public;

SELECT plan(16);

-- ─────────────────────────────────────────────────────────────────────────
--  LE MONTAGE
-- ─────────────────────────────────────────────────────────────────────────

DO $$
DECLARE
    u uuid := gen_random_uuid();
    v uuid := gen_random_uuid();
BEGIN
    INSERT INTO admin."user" (id) VALUES (u), (v);

    INSERT INTO admin.session (id, user_id, absolute_expires_at)
    VALUES ('44444444-4444-4444-8444-444444444444', u, now() + interval '1 hour');

    -- L'accréditation de quelqu'un d'autre, posée d'avance : le banc doit
    -- pouvoir prouver qu'elle est encore là à la fin.
    INSERT INTO webauthn.authenticator (id, user_id, credential_id, public_key, sign_count)
    VALUES ('11111111-1111-4111-8111-111111111111', v,
            '\xdeadbeef'::bytea, '\x01'::bytea, 7);

    PERFORM set_config('essai.u', u::text, false);
    PERFORM set_config('essai.v', v::text, false);
END $$;

SELECT isnt(
    nullif(current_setting('essai.u', true), ''),
    NULL,
    'the two accounts of this bench exist'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LES DEUX CAS QUI DOIVENT PASSER
--
--  Sans eux, une table qui refuserait TOUTE écriture ferait passer les douze
--  refus d'un coup.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO webauthn.authenticator
        (id, user_id, credential_id, public_key, sign_count)
      VALUES ('22222222-2222-4222-8222-222222222222',
              current_setting('essai.u')::uuid,
              '\xcafebabe'::bytea, '\x02'::bytea, 10)$$,
    'an authenticator is registered'
);

SELECT lives_ok(
    $$UPDATE webauthn.authenticator SET sign_count = 11
       WHERE id = '22222222-2222-4222-8222-222222222222'$$,
    'a counter that strictly increases is accepted'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LES DEUX FORMES DU SIGNAL
-- ═══════════════════════════════════════════════════════════════════════════

-- LA RÉGRESSION. Le cas manuel : un second exemplaire a signé moins souvent.
SELECT throws_ok(
    $$UPDATE webauthn.authenticator SET sign_count = 10
       WHERE id = '22222222-2222-4222-8222-222222222222'$$,
    'AD031', NULL,
    'a counter that goes backwards is refused'
);

-- LE COMPTEUR INCHANGÉ, et c'est celui qu'on oublie. Un authentificateur
-- authentique incrémente à CHAQUE assertion : présenter le même nombre veut
-- dire que l'assertion ne vient pas de lui. Une garde écrite `<` au lieu de
-- `<=` passerait ce cas, et seul ce banc voit la différence.
SELECT throws_ok(
    $$UPDATE webauthn.authenticator SET sign_count = 11
       WHERE id = '22222222-2222-4222-8222-222222222222'$$,
    'AD031', NULL,
    'a counter that does not move is refused just as firmly'
);

-- UNE ACCRÉDITATION EST UNIQUE. Deux enregistrements du même identifiant, et
-- l'un des deux compteurs cesse de vouloir dire quoi que ce soit.
SELECT throws_ok(
    $$INSERT INTO webauthn.authenticator
        (user_id, credential_id, public_key, sign_count)
      VALUES (current_setting('essai.u')::uuid,
              '\xcafebabe'::bytea, '\x03'::bytea, 0)$$,
    '23505', NULL,
    'the same credential cannot be registered twice'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE DÉSARMEMENT
-- ═══════════════════════════════════════════════════════════════════════════

-- L'ACCRÉDITATION D'UN AUTRE NE SE DÉSARME PAS. La fonction filtre sur
-- l'administrateur ET sur l'identifiant : sans la première moitié, connaître un
-- identifiant suffirait à couper l'accès de son porteur.
SELECT is(
    (SELECT count(*)::int FROM webauthn.disarm_clone(
        current_setting('essai.u')::uuid, '\xdeadbeef'::bytea)),
    0,
    'disarming somebody else''s credential does nothing'
);

SELECT is(
    (SELECT count(*)::int FROM webauthn.authenticator
      WHERE id = '11111111-1111-4111-8111-111111111111'
        AND revoked_at IS NULL),
    1,
    'and that credential is still live — the filter is on the owner too'
);

-- LE CAS RÉEL. Un appel, deux gestes.
SELECT is(
    (SELECT sessions_closed FROM webauthn.disarm_clone(
        current_setting('essai.u')::uuid, '\xcafebabe'::bytea)),
    1,
    'disarming a clone closes the live session in the same act'
);

SELECT is(
    (SELECT count(*)::int FROM webauthn.authenticator
      WHERE id = '22222222-2222-4222-8222-222222222222'
        AND revoked_at IS NOT NULL),
    1,
    'the credential is revoked'
);

-- SOUS SON PROPRE MOTIF. `SECURITY` nomme le rejeu d'un jeton de rafraîchissement
-- et dit autre chose. Un incident se relit des mois plus tard.
SELECT is(
    (SELECT end_reason::text FROM admin.session
      WHERE id = '44444444-4444-4444-8444-444444444444'),
    'CLONED',
    'the session is closed under CLONED, not under some generic reason'
);

-- UN SECOND PASSAGE NE SE PLAINT PAS. Le chemin qui mène ici est un chemin
-- d'incident : on y repasse, et une erreur au second appel ferait hésiter au
-- premier.
SELECT is(
    (SELECT count(*)::int FROM webauthn.disarm_clone(
        current_setting('essai.u')::uuid, '\xcafebabe'::bytea)),
    0,
    'disarming twice is quiet, because an incident path is walked twice'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UNE RÉVOCATION EST UN FAIT
--
--  Sans cette garde, rien n'empêchait de remettre `revoked_at` à NULL et de
--  ressusciter une accréditation condamnée.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$UPDATE webauthn.authenticator SET revoked_at = NULL
       WHERE id = '22222222-2222-4222-8222-222222222222'$$,
    'AD032', NULL,
    'a revocation is never lifted'
);

SELECT throws_ok(
    $$UPDATE webauthn.authenticator SET revoked_at = now() + interval '1 day'
       WHERE id = '22222222-2222-4222-8222-222222222222'$$,
    'AD032', NULL,
    'nor re-dated, which would move when the incident happened'
);

SELECT throws_ok(
    $$DELETE FROM webauthn.authenticator
       WHERE id = '22222222-2222-4222-8222-222222222222'$$,
    'AD040', NULL,
    'nor deleted, which would erase that the incident happened at all'
);

SELECT is(
    (SELECT count(*)::int FROM webauthn.authenticator
      WHERE id = '22222222-2222-4222-8222-222222222222'
        AND revoked_at IS NOT NULL
        AND sign_count = 11),
    1,
    'the disarmed credential is still there, with the counter that betrayed it'
);

SELECT * FROM finish();
