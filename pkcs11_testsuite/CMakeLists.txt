cmake_minimum_required(VERSION 3.16)
project(pkcs11_testsuite C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find dl library for dynamic loading
find_library(DL_LIB dl REQUIRED)

# pkg-config for optional dependencies
find_package(PkgConfig QUIET)

# Include directories
include_directories(include)
include_directories(/usr/include/softhsm)

# ---- Test application (interactive CLI) ----
add_executable(pkcs11_app
    src/pkcs11_app.c
    src/pkcs11_loader.c
    src/pkcs11_utils.c
)
target_link_libraries(pkcs11_app ${DL_LIB})

# ---- Test runner ----
add_executable(pkcs11_test
    src/pkcs11_loader.c
    src/pkcs11_utils.c
    tests/test_main.c
    tests/test_init.c
    tests/test_slot_token.c
    tests/test_session.c
    tests/test_login.c
    tests/test_objects.c
    tests/test_crypto_sym.c
    tests/test_crypto_asym.c
    tests/test_digest.c
    tests/test_random.c
    tests/test_key_generation.c
    tests/test_wrap_unwrap.c
    tests/test_derive.c
    tests/test_dual_function.c
    tests/test_parallel.c
    tests/test_edge_cases.c
    tests/test_req_general.c
    tests/test_req_session.c
    tests/test_req_objects.c
    tests/test_req_crypto.c
)
target_link_libraries(pkcs11_test ${DL_LIB} pthread)

# ---- Setup helper ----
add_executable(pkcs11_setup
    src/pkcs11_setup.c
    src/pkcs11_loader.c
    src/pkcs11_utils.c
)
target_link_libraries(pkcs11_setup ${DL_LIB})

install(TARGETS pkcs11_app pkcs11_test pkcs11_setup DESTINATION bin)
