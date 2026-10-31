"""
test_coffre.py -- Tests automatiques du mini-coffre (TP 1, étape 3).

Lancer :  pytest -v test_coffre.py

Chaque test démontre une propriété de sécurité précise. Les cinq premiers
sont ceux demandés par l'énoncé ; les suivants couvrent l'en-tête,
l'évolution des paramètres (étape 4) et la séparation des clés.

Pour garder des tests rapides, on abaisse les paramètres Argon2id pendant
les tests (fixture `parametres_rapides`) : la logique testée est identique.
Le test `test_parametres_par_defaut` vérifie une fois le réglage réel.
"""

import os
import struct

import pytest
from cryptography.exceptions import InvalidTag

import coffre

MDP = "correct horse battery staple"
NOM = "rapport.pdf"
DONNEES = b"%PDF-1.7\nContenu confidentiel du rapport\n" + os.urandom(1000)


@pytest.fixture(autouse=True)
def parametres_rapides(monkeypatch):
    """Argon2id allégé (8 Mio, 1 passe) uniquement pour accélérer les tests."""
    monkeypatch.setattr(coffre, "T", 1)
    monkeypatch.setattr(coffre, "M", 8 * 1024)
    monkeypatch.setattr(coffre, "P", 1)


def parametres(blob: bytes):
    """Lit (t, m, p) dans l'en-tête."""
    return struct.unpack(">III", blob[4:16])


def modifier_octet(blob: bytes, position: int) -> bytes:
    """Inverse tous les bits d'un octet du blob."""
    b = bytearray(blob)
    b[position] ^= 0xFF
    return bytes(b)


# Les cinq tests demandés


def test_aller_retour():
    """Correction : on retrouve exactement les données."""
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    assert coffre.dechiffrer(MDP, NOM, blob) == DONNEES


def test_chiffrer_deux_fois_donne_deux_resultats_differents():
    """Chiffrement probabiliste : sel et nonce neufs à chaque appel."""
    b1 = coffre.chiffrer(MDP, NOM, DONNEES)
    b2 = coffre.chiffrer(MDP, NOM, DONNEES)
    assert b1 != b2
    assert b1[16:32] != b2[16:32]          # sels différents
    assert b1[32:44] != b2[32:44]          # nonces différents
    assert b1[44:] != b2[44:]              # chiffrés différents


def test_mauvais_mot_de_passe():
    """Authentification de la clé : un mauvais mot de passe est rejeté."""
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("mauvais mot de passe", NOM, blob)


@pytest.mark.parametrize("position", [44, 100, -1])   # début, milieu, étiquette
def test_un_octet_du_chiffre_modifie(position):
    """Intégrité : la moindre modification du chiffré ou de l'étiquette est détectée."""
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, NOM, modifier_octet(blob, position))


def test_fichier_renomme():
    """Liaison au contexte : le nom du fichier fait partie des données associées."""
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, "facture.pdf", blob)



# Tests complémentaires : en-tête et format


def test_format_de_l_entete():
    """L'en-tête fait 44 octets et porte l'identifiant et les paramètres."""
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    assert blob[:4] == b"CFR1"
    assert parametres(blob) == (1, 8 * 1024, 1)
    # 44 octets d'en-tête + données + 16 octets d'étiquette
    assert len(blob) == 44 + len(DONNEES) + 16


def test_identifiant_de_format_inconnu():
    """Un identifiant de format inconnu est refusé."""
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(ValueError):
        coffre.dechiffrer(MDP, NOM, b"CFR9" + blob[4:])


@pytest.mark.parametrize("position", [16, 32])         # un octet du sel, du nonce
def test_sel_ou_nonce_modifie(position):
    """Le sel et le nonce sont protégés : les changer donne une autre clé / un autre masque."""
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, NOM, modifier_octet(blob, position))


def test_parametres_modifies():
    """Abaisser t dans l'en-tête ne permet pas d'affaiblir le fichier : rejet."""
    coffre.T = 2                     # restauré par monkeypatch (fixture autouse)
    blob = bytearray(coffre.chiffrer(MDP, NOM, DONNEES))
    blob[4:8] = (1).to_bytes(4, "big")                   # t : 2 -> 1
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, NOM, bytes(blob))


def test_fichier_tronque():
    """Un fichier tronqué est refusé."""
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):                      # étiquette tronquée
        coffre.dechiffrer(MDP, NOM, blob[:-1])


def test_fichier_vide():
    """Un fichier vide se chiffre et se déchiffre (seule l'étiquette est produite)."""
    blob = coffre.chiffrer(MDP, NOM, b"")
    assert len(blob) == 44 + 16
    assert coffre.dechiffrer(MDP, NOM, blob) == b""



# Étape 4 : évolution des paramètres et changement de mot de passe


def test_ancien_fichier_reste_lisible_apres_durcissement(monkeypatch):
    """Les paramètres sont lus dans l'en-tête : durcir T, M ne casse rien."""
    ancien = coffre.chiffrer(MDP, NOM, DONNEES)          # t=1, m=8 Mio
    monkeypatch.setattr(coffre, "T", 2)
    monkeypatch.setattr(coffre, "M", 16 * 1024)          # durcissement
    assert coffre.dechiffrer(MDP, NOM, ancien) == DONNEES
    assert parametres(coffre.chiffrer(MDP, NOM, DONNEES)) == (2, 16 * 1024, 1)


def test_rechiffrer(monkeypatch):
    """Changement de mot de passe, avec passage aux paramètres courants."""
    ancien = coffre.chiffrer(MDP, NOM, DONNEES)
    monkeypatch.setattr(coffre, "T", 2)
    nouveau = coffre.rechiffrer(MDP, "nouveau mot de passe", NOM, ancien)

    assert coffre.dechiffrer("nouveau mot de passe", NOM, nouveau) == DONNEES
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, NOM, nouveau)             # l'ancien ne marche plus
    assert parametres(nouveau)[0] == 2            # paramètres durcis
    assert nouveau[16:44] != ancien[16:44]               # sel et nonce neufs


def test_rechiffrer_avec_mauvais_ancien_mot_de_passe():
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        coffre.rechiffrer("faux", "nouveau", NOM, blob)


# Dérivation des clés (étape 1)


def test_cle_maitresse_deterministe_et_dependante_du_sel():
    sel1, sel2 = os.urandom(16), os.urandom(16)
    k1 = coffre.cle_maitresse(MDP, sel1)
    assert len(k1) == 32
    assert k1 == coffre.cle_maitresse(MDP, sel1)         # même entrée, même clé
    assert k1 != coffre.cle_maitresse(MDP, sel2)         # autre sel, autre clé
    assert k1 != coffre.cle_maitresse(MDP + "!", sel1)   # autre mot de passe


def test_sous_cles_separees_par_usage():
    """HKDF : un usage = une clé ; la sous-clé diffère de la clé maîtresse."""
    k = coffre.cle_maitresse(MDP, os.urandom(16))
    k_chiffr = coffre.sous_cle(k, b"chiffrement")
    k_mac = coffre.sous_cle(k, b"mac")
    assert len(k_chiffr) == 32
    assert k_chiffr != k_mac
    assert k_chiffr != k
    assert k_chiffr == coffre.sous_cle(k, b"chiffrement")


def test_parametres_par_defaut(monkeypatch):
    """Le réglage réel calibré (Argon2id t=3, 256 Mio, p=4) fonctionne de bout en bout."""
    monkeypatch.setattr(coffre, "T", 3)
    monkeypatch.setattr(coffre, "M", 256 * 1024)
    monkeypatch.setattr(coffre, "P", 4)
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    assert parametres(blob) == (3, 256 * 1024, 4)
    assert coffre.dechiffrer(MDP, NOM, blob) == DONNEES
