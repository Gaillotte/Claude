cmake_minimum_required(VERSION 3.16)
project(ipad_lib VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─── Options ──────────────────────────────────────────────────────────────────
option(IPAD_MOCK_TELSDK  "Use mock TelSDK (for testing without hardware)" OFF)
option(BUILD_APP          "Build ncurses TUI application"                  ON)
option(BUILD_TESTS        "Build test suite"                               ON)
option(BUILD_COVERAGE     "Enable gcov coverage instrumentation"           OFF)

# ─── Find packages ────────────────────────────────────────────────────────────
if(NOT IPAD_MOCK_TELSDK)
    # Real TelSDK: expect TELSDK_ROOT env variable
    if(NOT DEFINED TELSDK_ROOT)
        set(TELSDK_ROOT "$ENV{TELSDK_ROOT}")
    endif()
    if(NOT TELSDK_ROOT)
        message(FATAL_ERROR
            "TELSDK_ROOT is not set. Set it to the Qualcomm TelSDK install path, "
            "or configure with -DIPAD_MOCK_TELSDK=ON for testing without hardware.")
    endif()
    message(STATUS "TelSDK root: ${TELSDK_ROOT}")
endif()

# ─── Coverage flags ───────────────────────────────────────────────────────────
if(BUILD_COVERAGE)
    add_compile_options(--coverage -O0 -fprofile-arcs -ftest-coverage)
    add_link_options(--coverage)
endif()

# ─── Compile flags ────────────────────────────────────────────────────────────
add_compile_options(-Wall -Wextra -Wpedantic)

# ─── TelSDK version string ────────────────────────────────────────────────────
if(IPAD_MOCK_TELSDK)
    set(TELSDK_VERSION "mock-1.0")
else()
    set(TELSDK_VERSION "TelSDK-SA525")
endif()
add_compile_definitions(TELSDK_VERSION_STRING="${TELSDK_VERSION}")

# ═════════════════════════════════════════════════════════════════════════════
# Library target: ipad
# ═════════════════════════════════════════════════════════════════════════════
add_library(ipad SHARED src/ipad.cpp src/ipad_log.cpp)

target_include_directories(ipad
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if(IPAD_MOCK_TELSDK)
    target_include_directories(ipad PRIVATE tests/mocks)
    target_compile_definitions(ipad PUBLIC IPAD_MOCK_TELSDK=1)
    # Override TelSDK headers with mocks
    target_include_directories(ipad BEFORE PRIVATE tests/mocks)
else()
    target_include_directories(ipad PRIVATE ${TELSDK_ROOT}/include)
    target_link_directories(ipad PUBLIC ${TELSDK_ROOT}/lib)
    target_link_libraries(ipad PUBLIC telux_tel telux_common)
endif()

target_link_libraries(ipad PRIVATE pthread)

set_target_properties(ipad PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# ═════════════════════════════════════════════════════════════════════════════
# Application target: ipad_app
# ═════════════════════════════════════════════════════════════════════════════
if(BUILD_APP)
    find_package(Curses REQUIRED)

    add_executable(ipad_app app/src/ipad_app.cpp)
    target_include_directories(ipad_app PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CURSES_INCLUDE_DIR}
    )
    if(IPAD_MOCK_TELSDK)
        target_include_directories(ipad_app PRIVATE tests/mocks)
        target_compile_definitions(ipad_app PRIVATE IPAD_MOCK_TELSDK=1)
    endif()
    target_link_libraries(ipad_app PRIVATE ipad ${CURSES_LIBRARIES} pthread)
endif()

# ═════════════════════════════════════════════════════════════════════════════
# Tests
# ═════════════════════════════════════════════════════════════════════════════
if(BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)

    # Helper to add a test target
    function(add_ipad_test name sources)
        add_executable(${name} ${sources})
        target_include_directories(${name} PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/tests
            ${CMAKE_SOURCE_DIR}/tests/mocks
        )
        target_compile_definitions(${name} PRIVATE IPAD_MOCK_TELSDK=1)
        # Include mocks before any TelSDK headers
        target_include_directories(${name} BEFORE PRIVATE tests/mocks)
        target_link_libraries(${name} PRIVATE
            ipad
            GTest::GTest
            GTest::Main
            pthread
        )
        add_test(NAME ${name} COMMAND ${name})
        set_tests_properties(${name} PROPERTIES
            TIMEOUT 60
            LABELS  "ipad"
        )
    endfunction()

    # ── Unit tests ─────────────────────────────────────────────────────────
    add_ipad_test(ipad_unit_tests tests/unit/test_ipad_unit.cpp)

    # ── Log sink tests ─────────────────────────────────────────────────────
    add_ipad_test(ipad_log_tests tests/unit/test_ipad_log.cpp)

    # ── Integration tests ──────────────────────────────────────────────────
    add_ipad_test(ipad_integration_tests tests/integration/test_ipad_integration.cpp)

    # ── Vector runner ──────────────────────────────────────────────────────
    find_package(nlohmann_json QUIET)
    if(nlohmann_json_FOUND OR EXISTS "${CMAKE_SOURCE_DIR}/tests/vectors/nlohmann")
        add_ipad_test(ipad_vector_runner tests/vectors/test_vectors_runner.cpp)
        if(nlohmann_json_FOUND)
            target_link_libraries(ipad_vector_runner PRIVATE nlohmann_json::nlohmann_json)
        else()
            target_include_directories(ipad_vector_runner PRIVATE tests/vectors/nlohmann)
        endif()
        target_compile_definitions(ipad_vector_runner PRIVATE
            VECTORS_PATH="${CMAKE_SOURCE_DIR}/tests/vectors/test_vectors.json")
        set_tests_properties(ipad_vector_runner PROPERTIES
            ENVIRONMENT "GTEST_OUTPUT=xml:${CMAKE_BINARY_DIR}/test_results/vectors.xml"
        )
    else()
        message(STATUS "nlohmann/json not found — vector runner disabled. "
                       "Install with: apt install nlohmann-json3-dev")
    endif()

    # ── Benchmark suite ────────────────────────────────────────────────────
    add_ipad_test(ipad_bench tests/bench/bench_ipad.cpp)
    set_tests_properties(ipad_bench PROPERTIES
        TIMEOUT 120
        LABELS  "bench"
    )

    # ── CTest labels ───────────────────────────────────────────────────────
    set_tests_properties(ipad_unit_tests PROPERTIES LABELS "unit")
    set_tests_properties(ipad_integration_tests PROPERTIES LABELS "integration")
endif()

# ═════════════════════════════════════════════════════════════════════════════
# KPI report — generated after every build of the ipad library
# ═════════════════════════════════════════════════════════════════════════════
find_package(Python3 QUIET COMPONENTS Interpreter)
if(Python3_FOUND)
    set(KPI_REPORT "${CMAKE_BINARY_DIR}/ipad_kpi_report.pdf")
    set(KPI_SCRIPT "${CMAKE_SOURCE_DIR}/tools/gen_kpi_report.py")
    add_custom_command(
        TARGET ipad POST_BUILD
        COMMAND ${Python3_EXECUTABLE} ${KPI_SCRIPT}
                    --build-dir   "${CMAKE_BINARY_DIR}"
                    --source-dir  "${CMAKE_SOURCE_DIR}"
                    --output      "${KPI_REPORT}"
        COMMENT "Generating KPI report → ${KPI_REPORT}"
        VERBATIM
    )
    message(STATUS "KPI report: ${KPI_REPORT} (generated after each build)")
else()
    message(STATUS "Python3 not found — KPI report disabled")
endif()

# ═════════════════════════════════════════════════════════════════════════════
# Install rules
# ═════════════════════════════════════════════════════════════════════════════
include(GNUInstallDirs)

install(TARGETS ipad
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/ipad DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(BUILD_APP)
    install(TARGETS ipad_app RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# ─── Package config ───────────────────────────────────────────────────────────
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/ipadConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)
