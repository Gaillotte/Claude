# Building SoftHSM 2.7 for Windows with Visual Studio

This guide explains how to compile SoftHSM 2.7 on Windows using Visual Studio 2022,
producing native Windows binaries with no third-party runtime dependencies beyond OpenSSL.

---

## Prerequisites

Install the following tools in order before starting the build.

### 1. Visual Studio 2022 Community

Download from: https://visualstudio.microsoft.com/vs/community/

During installation, select the **"Desktop development with C++"** workload.
This installs the MSVC compiler, linker, and Windows SDK.

### 2. Git for Windows

Download from: https://git-scm.com/download/win

Use default settings during installation.

### 3. CMake

Download the `.msi` Windows installer from: https://cmake.org/download/

During installation, select **"Add CMake to the system PATH for all users"**.

### 4. OpenSSL for Windows (Full version)

Download from: https://slproweb.com/products/Win32OpenSSL.html

- Choose **Win64 OpenSSL v3.x.x** — the **full** installer (not "Light", ~7 MB)
- Install to: `C:\OpenSSL-Win64`
- When prompted, choose **"Copy OpenSSL DLLs to the OpenSSL binaries directory"**

---

## Build Steps

### Step 1 — Clone the SoftHSM repository

Open a standard **Command Prompt** and run:

```cmd
git clone https://github.com/opendnssec/SoftHSMv2.git
cd SoftHSMv2
git checkout 2.7.0
```

### Step 2 — Open the Developer Command Prompt

Search in the Windows Start menu for:

> **x64 Native Tools Command Prompt for VS 2022**

This sets up the correct compiler environment variables for 64-bit builds.
Navigate to the cloned source directory:

```cmd
cd path\to\SoftHSMv2
```

### Step 3 — Configure with CMake

Create a build directory and run CMake configuration:

```cmd
mkdir build
cd build

cmake .. ^
  -G "Visual Studio 17 2022" -A x64 ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DENABLE_GOST=OFF ^
  -DENABLE_SQLITE3=OFF ^
  -DWITH_OPENSSL=ON ^
  -DOPENSSL_ROOT_DIR="C:/OpenSSL-Win64" ^
  -DCMAKE_INSTALL_PREFIX="C:/SoftHSM2"
```

**CMake flag reference:**

| Flag | Value | Description |
|------|-------|-------------|
| `-G` | `"Visual Studio 17 2022"` | Use VS 2022 generator |
| `-A x64` | `x64` | Target 64-bit Windows |
| `ENABLE_GOST` | `OFF` | Disable GOST algorithm (requires extra libs) |
| `ENABLE_SQLITE3` | `OFF` | Disable SQLite token backend |
| `OPENSSL_ROOT_DIR` | `C:/OpenSSL-Win64` | Path to your OpenSSL installation |
| `CMAKE_INSTALL_PREFIX` | `C:/SoftHSM2` | Where to install the final binaries |

### Step 4 — Build

```cmd
cmake --build . --config Release
```

This compiles the source. It may take a few minutes.

### Step 5 — Install

```cmd
cmake --install . --config Release
```

This copies the built files to `C:\SoftHSM2`.

---

## Output

After install, `C:\SoftHSM2` will contain:

```
C:\SoftHSM2\
├── bin\
│   └── softhsm2-util.exe       # Command-line management tool
├── lib\
│   └── softhsm2.dll            # PKCS#11 library (point your application here)
├── etc\
│   └── softhsm2.conf           # Configuration file
└── share\
    └── man\                    # Manual pages
```

---

## Runtime Dependencies

The only DLLs you need to ship alongside `softhsm2.dll` are from OpenSSL:

```
C:\OpenSSL-Win64\bin\libssl-3-x64.dll
C:\OpenSSL-Win64\bin\libcrypto-3-x64.dll
```

Copy these into the same folder as `softhsm2.dll` for a self-contained distribution.

---

## First-Time Setup

### 1. Set the configuration environment variable

In a Command Prompt (run as Administrator if setting system-wide):

```cmd
setx SOFTHSM2_CONF "C:\SoftHSM2\etc\softhsm2.conf"
```

Or set it per-user without admin rights:

```cmd
setx SOFTHSM2_CONF "C:\SoftHSM2\etc\softhsm2.conf"
```

### 2. Edit the configuration file

Open `C:\SoftHSM2\etc\softhsm2.conf` and set the token storage directory:

```
directories.tokendir = C:\SoftHSM2\tokens
```

Create the tokens directory:

```cmd
mkdir C:\SoftHSM2\tokens
```

### 3. Initialize a token slot

```cmd
C:\SoftHSM2\bin\softhsm2-util.exe --init-token --slot 0 --label "MyToken"
```

You will be prompted to set a **SO PIN** (security officer) and a **User PIN**.

### 4. Verify the token is visible

```cmd
C:\SoftHSM2\bin\softhsm2-util.exe --show-slots
```

---

## Troubleshooting

### CMake cannot find OpenSSL

**Error:** `Could not find OpenSSL`

**Fix:** Confirm OpenSSL is installed at `C:\OpenSSL-Win64` and that `libcrypto.lib` exists at `C:\OpenSSL-Win64\lib\`.
Re-run cmake with the explicit path:

```cmd
-DOPENSSL_ROOT_DIR="C:/OpenSSL-Win64"
-DOPENSSL_INCLUDE_DIR="C:/OpenSSL-Win64/include"
```

### Build fails with GOST-related errors

**Fix:** Add `-DENABLE_GOST=OFF` to the cmake command (already included in this guide).

### `softhsm2-util.exe` reports missing DLL

**Fix:** Copy `libssl-3-x64.dll` and `libcrypto-3-x64.dll` from `C:\OpenSSL-Win64\bin\`
into the same directory as `softhsm2-util.exe`.

### Wrong Visual Studio generator

If you have VS 2019 instead of 2022, change the generator flag:

```cmd
-G "Visual Studio 16 2019"
```

---

## Tested Configuration

| Component | Version |
|-----------|---------|
| SoftHSM | 2.7.0 |
| Visual Studio | 2022 (v17) |
| CMake | 3.x |
| OpenSSL | 3.x (Win64) |
| Target platform | Windows x64 |
