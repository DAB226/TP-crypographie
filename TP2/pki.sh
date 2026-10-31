#!/bin/bash
# pki.sh -- TP 2 : construit la racine, l'intermédiaire, le serveur et le client.
# S'arrête à la première erreur. À lancer dans le dossier contenant racine.cnf et inter.cnf.
set -euo pipefail

# Arborescence des deux autorités (étape 1, annexe B)
for ac in racine inter; do
  mkdir -p "$ac/certs" "$ac/crl" "$ac/newcerts"
  : > "$ac/index.txt"
done
echo 1000 > racine/serial; echo 1000 > racine/crlnumber
echo 2000 > inter/serial;  echo 2000 > inter/crlnumber

# Étape 2 -- AC racine
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
  -out racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
  -subj "/C=BF/O=Universite TP/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out racine/racine.crt

# Étape 3 -- AC intermédiaire, signée par la racine
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out inter/inter.key
openssl req -new -key inter/inter.key \
  -subj "/C=BF/O=Universite TP/CN=Intermediaire TP" -out inter/inter.csr
openssl ca -batch -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt

# Étape 4 -- Serveur www.tp.local
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out serveur.key
openssl req -new -key serveur.key -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out serveur.csr
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in serveur.csr -out serveur.crt

# Étape 4 -- Client alice@tp.local
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out alice.key
openssl req -new -key alice.key -subj "/CN=alice@tp.local" \
  -addext "subjectAltName=email:alice@tp.local" -out alice.csr
openssl ca -batch -config inter.cnf -extensions ext_client -days 90 \
  -in alice.csr -out alice.crt
