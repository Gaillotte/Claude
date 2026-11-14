cmake_minimum_required(VERSION 3.16)
project(widget CXX)

# Every construct below is ordinary and must not be reported. The near-misses
# are deliberate: they are the forms that an unmeasured rule flags.

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fstack-protector-strong")

# A credential read from the environment, and a variable whose NAME contains
# TOKEN but whose value is an rpath marker. Both appear in real CMake and
# neither is a hardcoded secret.
set(DROP_SITE_PASSWORD "${CTEST_DROP_SITE_PASSWORD}")
set(CMAKE_SHARED_LIBRARY_RPATH_ORIGIN_TOKEN "\$ORIGIN")

# execute_process is in 106 of 1116 real CMake files. Only one that runs a
# downloader or a shell is a finding.
execute_process(COMMAND git rev-parse --short HEAD
                OUTPUT_VARIABLE GIT_REV OUTPUT_STRIP_TRAILING_NEWLINE)
execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/gen")

# A download over TLS, pinned by hash. This is the correct form.
file(DOWNLOAD https://example.test/libfoo-1.0.tar.gz "${CMAKE_BINARY_DIR}/libfoo.tgz"
     EXPECTED_HASH SHA256=0000000000000000000000000000000000000000000000000000000000000000)

# "URL" is overloaded in CMake: here it is a project homepage for the feature
# summary, not something to fetch. Two real CMake modules were failed by a rule
# that could not tell the difference.
include(FeatureSummary)
set_package_properties(LibXml2 PROPERTIES URL "http://xmlsoft.org/"
                       DESCRIPTION "XML parsing library")

# Path arithmetic relative to this file.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../cmake")

add_executable(widget src/main.cpp)
add_custom_command(TARGET widget POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:widget> "${CMAKE_BINARY_DIR}/bin/")
install(TARGETS widget RUNTIME DESTINATION bin)
