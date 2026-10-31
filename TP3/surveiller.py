#!/usr/bin/env python3
"""
surveiller.py -- Supervision des dates d'expiration des certificats d'un dossier.

"""

import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

SEUIL_ALERTE = 30
SEUIL_CRITIQUE = 7


def niveau(jours: int) -> str:
    if jours < SEUIL_CRITIQUE:
        return "CRITIQUE"
    if jours < SEUIL_ALERTE:
        return "ALERTE"
    return "OK"


def main(dossier: str) -> int:
    maintenant = datetime.now(timezone.utc)
    code = 0

    for fichier in sorted(Path(dossier).iterdir()):
        if not fichier.is_file():
            continue
        try:
            certificats = x509.load_pem_x509_certificates(fichier.read_bytes())
        except ValueError:
            continue                      # pas un fichier de certificats PEM

        for cert in certificats:
            jours = (cert.not_valid_after_utc - maintenant).days
            n = niveau(jours)
            print(f"{n:<9} {jours:>5} jours  {cert.subject.rfc4514_string():<40} ({fichier.name})")
            code = max(code, {"OK": 0, "ALERTE": 1, "CRITIQUE": 2}[n])

    return code


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage : surveiller.py <dossier>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
