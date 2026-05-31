# IPAd Abstraction Library

**IoT Profile Assistant Device (IPAd) — GSMA SGP.32**  
Backend : Qualcomm Telematics SDK (TelSDK) — SA525

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Application / Test IHM (TUI)               │
├─────────────────────────────────────────────────────────┤
│          libipad  (API publique C — ipad.h)              │
│  Init │ Profils │ eUICC │ Events │ Sécurité │ Diag      │
├─────────────────────────────────────────────────────────┤
│         Qualcomm TelSDK (telux::tel::ISimProfileManager) │
│                  ICardManager / SA525 BSP                │
├─────────────────────────────────────────────────────────┤
│                    eUICC physique (SA525)                │
└─────────────────────────────────────────────────────────┘
```

## Contenu du projet

```
ipad_lib/
├── include/ipad/
│   ├── ipad.h                      ← API publique C (stable)
│   └── ipad_telsdk_backend.h       ← Internals C++ / TelSDK
├── src/
│   └── ipad.cpp                    ← Implémentation principale
├── app/src/
│   └── ipad_app.cpp                ← IHM ncurses interactive
├── tests/
│   ├── mocks/
│   │   └── mock_telsdk.h           ← Mock complet TelSDK (sans HW)
│   ├── unit/
│   │   └── test_ipad_unit.cpp      ← Tests unitaires (30+ TCs)
│   ├── integration/
│   │   └── test_ipad_integration.cpp ← Tests workflows SGP.32
│   └── vectors/
│       ├── test_vectors.json        ← Vecteurs de test (JSON)
│       └── test_vectors_runner.cpp  ← Exécuteur automatique
├── .github/workflows/
│   └── ci.yml                      ← Pipeline CI/CD GitHub Actions
└── CMakeLists.txt
```

## Build — Mode mock (sans hardware SA525)

```bash
# Dépendances Ubuntu/Debian
sudo apt install cmake ninja-build libgtest-dev libgmock-dev \
                 nlohmann-json3-dev libncurses-dev

# Configurer et compiler
cmake -B build -DIPAD_MOCK_TELSDK=ON -DBUILD_TESTS=ON -DBUILD_APP=ON
cmake --build build --parallel $(nproc)

# Lancer les tests
cd build && ctest --output-on-failure

# Lancer l'IHM (mode mock)
./build/ipad_app --mock
```

## Build — Mode hardware (SA525 + TelSDK)

```bash
export TELSDK_ROOT=/opt/qualcomm/telematics-sdk

cmake -B build_hw \
  -DCMAKE_BUILD_TYPE=Release \
  -DIPAD_MOCK_TELSDK=OFF \
  -DTELSDK_ROOT=${TELSDK_ROOT}

cmake --build build_hw --parallel $(nproc)
```

## Tests

| Suite             | Commande ctest                          | Rapport        |
|-------------------|-----------------------------------------|----------------|
| Unitaires         | `ctest -L unit`                         | JUnit XML      |
| Intégration       | `ctest -L integration`                  | JUnit XML      |
| Vecteurs SGP.32   | `./ipad_vector_runner`                  | JUnit XML      |
| Couverture        | `cmake -DBUILD_COVERAGE=ON` + gcovr     | HTML + XML     |

## CI/CD (GitHub Actions)

Le pipeline `.github/workflows/ci.yml` exécute sur chaque push :

1. **Build + tests unitaires** — GCC 13 + Clang 17
2. **Tests d'intégration** — workflows SGP.32 complets
3. **Vecteurs de test** — exécution automatique des 30+ vecteurs JSON
4. **Analyse statique** — clang-tidy + cppcheck
5. **Cross-compile aarch64** — vérification binaire SA525 (branches main/release)
6. **Rapport consolidé** — JUnit fusionné

## Utilisation de l'IHM

```
Touches :
  i   Initialiser la connexion IPAd/TelSDK
  r   Rafraîchir la liste des profils
  d   Télécharger un profil (saisie Activation Code)
  e   Activer le profil sélectionné
  x   Désactiver le profil sélectionné
  D   Supprimer le profil sélectionné (confirmation)
  n   Renommer le profil sélectionné
  s   Self-test (HAL + transport)
  j   Export diagnostics JSON
  +/↓ Profil suivant
  -/↑ Profil précédent
  q   Quitter
```

## Normes de référence

- GSMA SGP.32 v1.0 — eSIM IoT Technical Specification
- Qualcomm Telematics SDK — telux::tel::ISimProfileManager
- GSMA SGP.22 v3.0 — RSP Technical Specification
