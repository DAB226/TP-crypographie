# Module EC1 – Ingénierie de la cryptographie

Travaux pratiques individuels, année universitaire 2026–2027.

Nom :  DABIRE Malyong Evrard


## TP 1 – Chiffrement authentifié et dérivation de clés

Un mini-coffre de fichiers chiffrés par mot de passe, en Python.

- `coffre.py` : chiffre et déchiffre un fichier avec AES-GCM. La clé est dérivée du mot de passe avec Argon2id, puis HKDF.
- `test_coffre.py` : tests automatiques (pytest) qui vérifient la confidentialité et l'intégrité.
- `compte_rendu_tp1.docx` : compte rendu.

## TP 2 – Infrastructure de gestion de clés

Une petite autorité de certification construite avec OpenSSL : une racine, une intermédiaire, un certificat de serveur et un certificat de client.

- `pki.sh` : script qui construit toute l'infrastructure.
- `racine.cnf`, `inter.cnf` : fichiers de configuration des deux autorités.
- `certificats/` : certificats publics et listes de révocation (aucune clé privée).
- `compte_rendu_tp2.docx` : compte rendu.

## TP 3 – Canal sécurisé et gestion des certificats

Un serveur web nginx en TLS avec authentification du client par certificat, puis la supervision et le renouvellement des certificats.

- `tp.conf` : configuration nginx.
- `surveiller.py` : surveille les dates d'expiration des certificats.
- `renouveler.sh` : renouvelle le certificat du serveur automatiquement.
- `capture_tls13.pcap` : capture d'une connexion TLS 1.3.
- `compte_rendu_tp3.docx` : compte rendu.


