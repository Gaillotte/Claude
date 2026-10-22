cmake_minimum_required(VERSION 3.16)
project(dispatch_probe)

# This file's extension is .txt. Without a basename branch in classify_file it
# is routed to the plain-text scanner, which has no CMake rules at all.
set(BUILD_SECRET_TOKEN "abcdef0123456789deadbeef")

add_executable(probe src/main.c)
