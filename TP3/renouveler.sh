#!/bin/bash
# renouveler.sh -- Renouvelle le certificat du serveur www.tp.local (TP 3, étape 6).
#
# À lancer en root, depuis n'importe où ; le script se place dans le dossier pki/ qui le contient
# (racine.cnf, inter.cnf, racine/, inter/). Il ne renouvelle que si le certificat installé
# expire dans moins de 30 jours.
#
# Planification quotidienne (crontab de root, "sudo crontab -e") :
#   0 3 * * * /chemin/vers/pki/renouveler.sh >> /var/log/renouveler.log 2>&1
set -euo pipefail
cd "$(dirname "$0")"

TLS=/etc/nginx/tls
JOURS=30

# Ne rien faire tant que le certificat actuel est valable plus de 30 jours
if openssl x509 -in "$TLS/serveur_chaine.crt" -noout -checkend $((JOURS * 86400)); then
  echo "$(date '+%F %T') Certificat valable plus de $JOURS jours : pas de renouvellement."
  exit 0
fi
echo "$(date '+%F %T') Le certificat expire dans moins de $JOURS jours : renouvellement."

# 1. Nouvelle clé et nouvelle demande de certificat
mkdir -p nouveau
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out nouveau/serveur.key
openssl req -new -key nouveau/serveur.key -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out nouveau/serveur.csr

# 2. Signature par l'intermédiaire
# (openssl ca refuse sinon un second certificat de même nom tant que le premier n'a pas expiré)
echo "unique_subject = no" > inter/index.txt.attr
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in nouveau/serveur.csr -out nouveau/serveur.crt
cat nouveau/serveur.crt inter/inter.crt > nouveau/serveur_chaine.crt

# 3. Vérification de la chaîne avant tout déploiement (set -e : arrêt si échec)
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local nouveau/serveur.crt

# 5. Conservation de l'ancien certificat et de l'ancienne clé pour pouvoir revenir en arrière
ANCIEN="$TLS/ancien/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$ANCIEN"
cp -p "$TLS/serveur.key" "$TLS/serveur_chaine.crt" "$ANCIEN/"

# 4. Installation, test de la configuration et rechargement sans interruption
install -m 600 nouveau/serveur.key "$TLS/serveur.key"
install -m 644 nouveau/serveur_chaine.crt "$TLS/serveur_chaine.crt"
nginx -t
systemctl reload nginx
echo "$(date '+%F %T') Nouveau certificat installé (ancien conservé dans $ANCIEN)."
