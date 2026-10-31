"""
coffre.py -- Mini-coffre de fichiers chiffrés par mot de passe (TP 1).

Format : "CFR1" (4) | t, m, p (12) | sel (16) | nonce (12) | chiffré + étiquette
Données associées : en-tête (44 octets) + nom du fichier.
"""

import os
import struct
import time

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Paramètres Argon2id : temps, mémoire (Kio), parallélisme.
# Énoncé : 3, 64 Mio, 4 -> 0,12 s mesurées ; ajustés pour viser ~0,5 s.
T, M, P = 4, 512 * 512, 4

MAGIC = b"CFR1"
TAILLE_ENTETE = 44


# Étape 1 -- Dérivation des clés

def cle_maitresse(mot_de_passe: str, sel: bytes, t=None, m=None, p=None) -> bytes:
    """Argon2id -> 32 octets (paramètres T, M, P par défaut, ceux de l'en-tête au déchiffrement)."""
    return hash_secret_raw(
        secret=mot_de_passe.encode(),
        salt=sel,
        time_cost=T if t is None else t,
        memory_cost=M if m is None else m,
        parallelism=P if p is None else p,
        hash_len=32,
        type=Type.ID,
    )


def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """HKDF-SHA256 avec info = b"coffre-v1|" + usage -> 32 octets."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"coffre-v1|" + usage,
    ).derive(maitresse)


# Étape 2 -- Chiffrer et déchiffrer

def chiffrer(mot_de_passe: str, nom: str, donnees: bytes) -> bytes:
    sel = os.urandom(16)
    nonce = os.urandom(12)
    entete = MAGIC + struct.pack(">III", T, M, P) + sel + nonce

    cle = sous_cle(cle_maitresse(mot_de_passe, sel, T, M, P), b"chiffrement")
    chiffre = AESGCM(cle).encrypt(nonce, donnees, entete + nom.encode())
    return entete + chiffre


def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    entete = blob[:TAILLE_ENTETE]
    if entete[:4] != MAGIC:
        raise ValueError("identifiant de format inconnu")

    t, m, p = struct.unpack(">III", entete[4:16])
    sel = entete[16:32]
    nonce = entete[32:44]

    cle = sous_cle(cle_maitresse(mot_de_passe, sel, t, m, p), b"chiffrement")
    # Lève InvalidTag si le mot de passe, l'en-tête, le nom ou le chiffré ne correspondent pas.
    return AESGCM(cle).decrypt(nonce, blob[TAILLE_ENTETE:], entete + nom.encode())


# Étape 4 -- Évolution

def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes) -> bytes:
    """Déchiffre avec l'ancien mot de passe (paramètres de l'en-tête),
    rechiffre avec le nouveau mot de passe et les paramètres courants T, M, P."""
    return chiffrer(nouveau_mdp, nom, dechiffrer(ancien_mdp, nom, blob))


# Mesure du temps d'une dérivation Argon2id (étape 1)

if __name__ == "__main__":
    debut = time.perf_counter()
    cle_maitresse("mot de passe", os.urandom(16))
    print(f"Argon2id t={T}, m={M // 1024} Mio, p={P} : {time.perf_counter() - debut:.3f} s")
