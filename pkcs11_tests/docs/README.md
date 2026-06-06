# PKCS11 Test Suite — SoftHSM2

Suite de tests complète pour l'API PKCS11 en utilisant **SoftHSM2** comme implémentation logicielle.

## Prérequis

- Python ≥ 3.10
- `softhsm2` (installé via `make install`)

## Démarrage rapide

```bash
cd pkcs11_tests

# 1. Installer SoftHSM2 et les dépendances Python
make install

# 2. Initialiser le token SoftHSM2
make init

# 3. Exporter les variables (affichées par init_softhsm.sh)
export PKCS11_MODULE_PATH="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_TOKEN_LABEL="TestToken"
export PKCS11_USER_PIN="1234"
export PKCS11_SO_PIN="12345678"

# 4. Lancer tous les tests avec rapport de couverture
make test
```

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `PKCS11_MODULE_PATH` | auto-détecté | Chemin vers `libsofthsm2.so` |
| `PKCS11_TOKEN_LABEL` | `TestToken` | Label du token initialisé |
| `PKCS11_USER_PIN` | `1234` | PIN utilisateur |
| `PKCS11_SO_PIN` | `12345678` | PIN Security Officer |

## Structure du projet

```
pkcs11_tests/
├── pkcs11_app/          # Application testée
│   ├── config.py        # Configuration (env vars)
│   ├── library.py       # Chargement de la lib PKCS11
│   ├── session.py       # Gestion des sessions
│   ├── token.py         # Gestion des objets/clés
│   └── crypto.py        # Opérations cryptographiques
├── tests/
│   ├── conftest.py          # Fixtures partagées
│   ├── test_config.py       # Config (tests unitaires)
│   ├── test_library.py      # Chargement bibliothèque
│   ├── test_session.py      # Sessions & authentification
│   ├── test_token.py        # Génération clés & objets
│   ├── test_crypto_aes.py   # AES-CBC / AES-ECB
│   ├── test_crypto_des3.py  # 3DES-CBC
│   ├── test_crypto_rsa.py   # RSA PKCS1 / OAEP / PSS
│   ├── test_crypto_ec.py    # ECDSA + courbes multiples
│   ├── test_digest.py       # SHA-1/256/384/512
│   ├── test_random.py       # RNG PKCS11
│   ├── test_key_wrapping.py # Wrap/Unwrap de clés
│   ├── test_attributes.py   # Attributs des objets
│   └── test_multisession.py # Sessions concurrentes
└── scripts/
    ├── install_softhsm.sh   # Installation
    ├── init_softhsm.sh      # Initialisation token
    └── reset_softhsm.sh     # Réinitialisation
```

## Commandes disponibles

```bash
make test            # Tous les tests + couverture
make test-fast       # Tests rapides (sans couverture, arrêt sur 1er échec)
make test-unit       # Tests unitaires uniquement (pas de HSM)
make coverage        # Rapport HTML dans coverage_html/
make reset           # Réinitialiser le token SoftHSM
make clean           # Nettoyer les artefacts
```

## Mécanismes PKCS11 testés

| Catégorie | Mécanismes |
|---|---|
| Chiffrement symétrique | AES-CBC-PAD, AES-ECB, DES3-CBC-PAD |
| Chiffrement asymétrique | RSA-PKCS, RSA-PKCS-OAEP |
| Signature | SHA256-RSA-PKCS, SHA256-RSA-PKCS-PSS, ECDSA-SHA256 |
| Digest | SHA-1, SHA-256, SHA-384, SHA-512 |
| Wrap/Unwrap | AES-KEY-WRAP-PAD |
| Aléatoire | GenerateRandom |
| Courbes EC | secp256r1, secp384r1, secp521r1 |
