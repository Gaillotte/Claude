# Installation Guide — Windows 11

This guide walks you through installing all prerequisites and running the full PKCS11 test suite (236 tests, 100% coverage) on Windows 11.

---

## Prerequisites overview

| Tool | Version | Purpose |
|---|---|---|
| Python | ≥ 3.10 | Runtime |
| Git | any | Clone the repository |
| SoftHSM2 for Windows | ≥ 2.6 | PKCS11 token emulator |
| Visual C++ Redistributable | 2015–2022 | Required by SoftHSM2 DLL |

---

## Step 1 — Install Python

1. Download the latest **Python 3.11** (or 3.10+) installer from https://www.python.org/downloads/windows/  
   Choose the **Windows installer (64-bit)**.

2. Run the installer.  
   **Important:** check **"Add Python to PATH"** before clicking Install.

3. Open **PowerShell** (Win + X → Terminal) and verify:
   ```powershell
   python --version
   # Python 3.11.x
   pip --version
   # pip 24.x ...
   ```

---

## Step 2 — Install Git

1. Download from https://git-scm.com/download/win and run the installer with default settings.

2. Verify:
   ```powershell
   git --version
   # git version 2.x.x
   ```

---

## Step 3 — Install SoftHSM2 for Windows

SoftHSM2 does not ship an official Windows installer. Use one of these options:

### Option A — Pre-built binary (recommended)

Download the latest pre-built release from:  
**https://github.com/disig/SoftHSM2-for-Windows/releases**

1. Download `SoftHSM2-*.msi` (or the ZIP archive).
2. Run the MSI installer (or extract the ZIP to `C:\SoftHSM2`).
3. The installer places files in:
   ```
   C:\Program Files\SoftHSM2\
   ├── bin\
   │   ├── softhsm2-util.exe
   │   └── softhsm2-dump-file.exe
   ├── lib\
   │   └── softhsm2.dll          ← PKCS11 module
   └── share\
       └── softhsm\softhsm2.conf.sample
   ```

4. Add `bin\` to your PATH (the MSI does this automatically):
   ```powershell
   # Verify
   softhsm2-util --version
   # 2.6.1
   ```

### Option B — Chocolatey

If you have [Chocolatey](https://chocolatey.org/) installed, run in an **elevated** PowerShell:
```powershell
choco install softhsm
```

### Option C — winget

```powershell
winget install SoftHSM2
```

---

## Step 4 — Configure SoftHSM2

SoftHSM2 needs a configuration file and a token storage directory.

### 4.1 Create directories

```powershell
New-Item -ItemType Directory -Force -Path "$env:APPDATA\SoftHSM2\tokens"
```

### 4.2 Create the configuration file

```powershell
$confDir = "$env:APPDATA\SoftHSM2"
$confFile = "$confDir\softhsm2.conf"

@"
directories.tokendir = $confDir\tokens\
objectstore.backend = file
log.level = ERROR
slots.removable = false
"@ | Set-Content -Path $confFile -Encoding UTF8
```

### 4.3 Point SoftHSM2 at the configuration file

```powershell
$env:SOFTHSM2_CONF = "$env:APPDATA\SoftHSM2\softhsm2.conf"
# Make it permanent for your user session:
[System.Environment]::SetEnvironmentVariable("SOFTHSM2_CONF", $env:SOFTHSM2_CONF, "User")
```

### 4.4 Initialize the test token

```powershell
softhsm2-util --init-token --free `
    --label "TestToken" `
    --so-pin "12345678" `
    --pin "1234"
```

Expected output:
```
Slot 0 has a free/uninitialized token.
The token has been initialized and is reassigned to slot 136323026
```

Verify:
```powershell
softhsm2-util --show-slots
```

---

## Step 5 — Clone the repository

```powershell
git clone https://github.com/Gaillotte/Claude.git
cd Claude\pkcs11_tests
```

---

## Step 6 — Create a virtual environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

> **Execution Policy note:** if PowerShell blocks the activation script, run once:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

---

## Step 7 — Install Python dependencies

```powershell
pip install -r requirements.txt
```

This installs:
- `python-pkcs11` — PKCS11 wrapper
- `pytest`, `pytest-cov`, `pytest-xdist`, `pytest-timeout`
- `cryptography`

> **Note on `python-pkcs11` on Windows:** the package is a Cython extension.  
> A pre-built wheel is available for Python 3.10/3.11 on PyPI. If `pip install` fails with a build error, install the **Visual C++ Build Tools** first:
> ```powershell
> winget install Microsoft.VisualStudio.2022.BuildTools
> ```
> Then retry `pip install python-pkcs11`.

---

## Step 8 — Set environment variables

Open PowerShell and set the variables for the current session:

```powershell
# Path to the SoftHSM2 PKCS11 DLL
# Adjust if you installed to a different location
$env:PKCS11_MODULE_PATH  = "C:\Program Files\SoftHSM2\lib\softhsm2.dll"
$env:PKCS11_TOKEN_LABEL  = "TestToken"
$env:PKCS11_USER_PIN     = "1234"
$env:PKCS11_SO_PIN       = "12345678"
$env:SOFTHSM2_CONF       = "$env:APPDATA\SoftHSM2\softhsm2.conf"
```

To make these variables **permanent** for your user account:

```powershell
[System.Environment]::SetEnvironmentVariable("PKCS11_MODULE_PATH",  "C:\Program Files\SoftHSM2\lib\softhsm2.dll", "User")
[System.Environment]::SetEnvironmentVariable("PKCS11_TOKEN_LABEL",  "TestToken",  "User")
[System.Environment]::SetEnvironmentVariable("PKCS11_USER_PIN",     "1234",       "User")
[System.Environment]::SetEnvironmentVariable("PKCS11_SO_PIN",       "12345678",   "User")
[System.Environment]::SetEnvironmentVariable("SOFTHSM2_CONF",       "$env:APPDATA\SoftHSM2\softhsm2.conf", "User")
```

> **Tip:** close and reopen PowerShell after setting permanent variables.

---

## Step 9 — Run the tests

Make sure the virtual environment is active, then from `pkcs11_tests\`:

```powershell
# Full test suite with coverage report
python -m pytest

# Quick run (no coverage, stop on first failure)
python -m pytest -x --no-cov

# Only unit tests (no HSM required)
python -m pytest -m unit --no-cov

# Specific test file
python -m pytest tests\test_crypto_aes.py -v --no-cov
```

### Expected output

```
============================= test session starts ==============================
platform win32 -- Python 3.11.x, pytest-9.x.x
collected 236 items

tests/test_aead.py ................                                      [  6%]
tests/test_attributes.py ......                                          [  9%]
...
tests/test_token.py .........................                            [100%]

================================ tests coverage ================================
Name                      Stmts   Miss  Cover
---------------------------------------------
pkcs11_app/__init__.py       11      0   100%
pkcs11_app/aead.py           33      0   100%
pkcs11_app/config.py         20      0   100%
pkcs11_app/crypto.py         87      0   100%
pkcs11_app/derive.py         37      0   100%
pkcs11_app/info.py           38      0   100%
pkcs11_app/library.py        25      0   100%
pkcs11_app/mac.py            45      0   100%
pkcs11_app/objects.py        59      0   100%
pkcs11_app/session.py        35      0   100%
pkcs11_app/token.py          47      0   100%
---------------------------------------------
TOTAL                       437      0   100%

236 passed in ~10s
```

---

## Step 10 — View the HTML coverage report

After running the tests, open the report in your browser:

```powershell
Start-Process "coverage_html\index.html"
```

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'pkcs11'`

The virtual environment is not active. Run:
```powershell
.venv\Scripts\Activate.ps1
```

### `RuntimeError: PKCS11 module not found`

The `PKCS11_MODULE_PATH` variable is not set or points to the wrong path. Verify the DLL exists:
```powershell
Test-Path $env:PKCS11_MODULE_PATH
# Must return: True
```

Common DLL locations depending on the install method:
| Install method | DLL path |
|---|---|
| MSI installer | `C:\Program Files\SoftHSM2\lib\softhsm2.dll` |
| ZIP extracted to `C:\SoftHSM2` | `C:\SoftHSM2\lib\softhsm2.dll` |
| Chocolatey | `C:\ProgramData\chocolatey\lib\softhsm\tools\SoftHSM2\lib\softhsm2.dll` |

### `RuntimeError: Token 'TestToken' not found`

The token was not initialized or `SOFTHSM2_CONF` points to the wrong file. Reinitialize:
```powershell
softhsm2-util --delete-token --token "TestToken"
softhsm2-util --init-token --free `
    --label "TestToken" `
    --so-pin "12345678" `
    --pin "1234"
```

### `OSError: [WinError 126] The specified module could not be found`

The SoftHSM2 DLL depends on the **Visual C++ Redistributable 2015–2022**. Install it:
```powershell
winget install Microsoft.VCRedist.2015+.x64
```

Then reopen PowerShell and retry.

### Tests hang or time out

The default test timeout is 60 seconds. If your machine is slow, increase it:
```powershell
python -m pytest --timeout=120 --no-cov
```

### `PinIncorrect` error after a failed `test_change_pin_and_back`

A test may have changed the PIN without restoring it. Reinitialize the token (Step 4.4) to reset all PINs to their defaults.

---

## Resetting the token

To wipe all keys and objects and start fresh:

```powershell
softhsm2-util --delete-token --token "TestToken"
softhsm2-util --init-token --free `
    --label "TestToken" `
    --so-pin "12345678" `
    --pin "1234"
```

---

## Quick-start summary

```powershell
# 1. Install SoftHSM2 (MSI from GitHub releases) and Python 3.11

# 2. Configure token
$env:SOFTHSM2_CONF = "$env:APPDATA\SoftHSM2\softhsm2.conf"
New-Item -ItemType Directory -Force "$env:APPDATA\SoftHSM2\tokens"
"directories.tokendir = $env:APPDATA\SoftHSM2\tokens\`nobjectstore.backend = file`nlog.level = ERROR" | Set-Content $env:SOFTHSM2_CONF
softhsm2-util --init-token --free --label TestToken --so-pin 12345678 --pin 1234

# 3. Clone and set up Python
git clone https://github.com/Gaillotte/Claude.git
cd Claude\pkcs11_tests
python -m venv .venv && .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 4. Set environment variables
$env:PKCS11_MODULE_PATH = "C:\Program Files\SoftHSM2\lib\softhsm2.dll"
$env:PKCS11_TOKEN_LABEL = "TestToken"
$env:PKCS11_USER_PIN    = "1234"
$env:PKCS11_SO_PIN      = "12345678"

# 5. Run tests
python -m pytest
```
