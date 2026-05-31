# IPAd Abstraction Library

**IoT Profile Assistant Device (IPAd) — GSMA SGP.32**  
Backend: Qualcomm Telematics SDK (TelSDK) — SA525

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│            Application / Test UI (TUI)                  │
├─────────────────────────────────────────────────────────┤
│         libipad  (public C API — ipad.h)                │
│  Init │ Profiles │ eUICC │ Events │ Security │ Diag     │
├─────────────────────────────────────────────────────────┤
│        Qualcomm TelSDK (telux::tel::ISimProfileManager) │
│                 ICardManager / SA525 BSP                │
├─────────────────────────────────────────────────────────┤
│                   Physical eUICC (SA525)                │
└─────────────────────────────────────────────────────────┘
```

## Project layout

```
ipad_lib/
├── include/ipad/
│   ├── ipad.h                      ← Public C API (stable)
│   ├── ipad_log.h                  ← Configurable log sink API
│   └── ipad_telsdk_backend.h       ← C++ / TelSDK internals
├── src/
│   ├── ipad.cpp                    ← Main implementation
│   └── ipad_log.cpp                ← Serial / TCP log sinks
├── app/src/
│   └── ipad_app.cpp                ← Interactive ncurses TUI
├── tests/
│   ├── mocks/
│   │   └── mock_telsdk.h           ← Full TelSDK mock (no HW required)
│   ├── unit/
│   │   ├── test_ipad_unit.cpp      ← Unit tests (30+ TCs)
│   │   └── test_ipad_log.cpp       ← Log sink tests
│   ├── integration/
│   │   └── test_ipad_integration.cpp ← SGP.32 workflow tests
│   └── vectors/
│       ├── test_vectors.json        ← JSON test vectors
│       └── test_vectors_runner.cpp  ← Automated vector runner
├── doc/
│   └── IPAd_Library_Reference.docx ← Full developer reference manual
├── tools/
│   ├── gen_kpi_report.py            ← PDF KPI report generator
│   └── gen_doc.py                   ← Word documentation generator
└── CMakeLists.txt
```

## Build — Mock mode (no SA525 hardware)

```bash
# Dependencies (Ubuntu/Debian)
sudo apt install cmake ninja-build libgtest-dev libgmock-dev \
                 nlohmann-json3-dev libncurses-dev
pip install reportlab   # for PDF KPI report

# Configure and build
cmake -B build -DIPAD_MOCK_TELSDK=ON -DBUILD_TESTS=ON -DBUILD_APP=ON
cmake --build build --parallel $(nproc)

# Run tests
cd build && ctest --output-on-failure

# Launch the TUI (mock mode)
./build/ipad_app --mock
```

## Build — Hardware mode (SA525 + TelSDK)

```bash
export TELSDK_ROOT=/opt/qualcomm/telematics-sdk

cmake -B build_hw \
  -DCMAKE_BUILD_TYPE=Release \
  -DIPAD_MOCK_TELSDK=OFF \
  -DTELSDK_ROOT=${TELSDK_ROOT}

cmake --build build_hw --parallel $(nproc)
```

## CMake options

| Option              | Default | Description                                              |
|---------------------|---------|----------------------------------------------------------|
| `IPAD_MOCK_TELSDK`  | OFF     | Use in-process mock instead of real TelSDK               |
| `BUILD_APP`         | ON      | Build the ncurses TUI demo application                   |
| `BUILD_TESTS`       | ON      | Build the GTest test suite                               |
| `BUILD_COVERAGE`    | OFF     | Instrument with gcov for coverage measurement            |

## Test suites

| Suite              | ctest command                       | Report         |
|--------------------|-------------------------------------|----------------|
| Unit               | `ctest -L unit`                     | JUnit XML      |
| Integration        | `ctest -L integration`              | JUnit XML      |
| SGP.32 vectors     | `./ipad_vector_runner`              | JUnit XML      |
| Log sinks          | `ctest -R ipad_log_tests`           | JUnit XML      |
| Coverage           | `cmake -DBUILD_COVERAGE=ON` + gcovr | HTML + XML     |

## Python port

A complete Python 3.9+ port is available in `../ipad_python/`:

```bash
cd ../ipad_python
pip install pytest
pytest tests/ -v   # 54 tests
```

## KPI report

A PDF KPI report (`ipad_kpi_report.pdf`) is automatically generated in the
build directory after every `cmake --build` invocation. It includes binary
size, section breakdown, RAM consumption, and flash/RAM usage bars vs the
SA525 target.

## TUI key bindings

```
Key   Action
─────────────────────────────────
i     Initialise IPAd / TelSDK
r     Refresh profile list
d     Download profile (enter Activation Code)
e     Enable selected profile
x     Disable selected profile
D     Delete selected profile (confirmation required)
n     Rename selected profile
s     Self-test (HAL + transport + crypto)
j     Export diagnostics to JSON
+/↓   Next profile
-/↑   Previous profile
q     Quit
```

## Reference standards

- GSMA SGP.32 v1.0 — eSIM IoT Technical Specification
- Qualcomm Telematics SDK — `telux::tel::ISimProfileManager`
- GSMA SGP.22 v3.0 — RSP Technical Specification
