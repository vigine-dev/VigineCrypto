cmake_minimum_required(VERSION 3.25)

project(VigineCrypto CXX C ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(VIGINECRYPTO_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})

option(VIGINECRYPTO_BUILD_TESTS "Build VigineCrypto tests" ON)

if(NOT DEFINED CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

# --- vendored backends ---------------------------------------------------
# libcrypto (Ed25519, AES-256-GCM, CSPRNG; TLS later). OpenSSL is not a CMake
# project, so this module drives its Perl/make build via ExternalProject and
# exposes the vigine::openssl::crypto target.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/VendorOpenSSL.cmake)

# BLAKE3 content-addressing hashes. The reference C library ships its own
# CMake, so a plain add_subdirectory suffices.
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/blake3/c ${CMAKE_BINARY_DIR}/blake3 EXCLUDE_FROM_ALL)

# --- facade library ------------------------------------------------------
file(GLOB VIGINECRYPTO_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
file(GLOB VIGINECRYPTO_HEADERS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/include/vigine/crypto/*.h)

add_library(VigineCrypto STATIC ${VIGINECRYPTO_SOURCES} ${VIGINECRYPTO_HEADERS})
add_library(VigineCrypto::VigineCrypto ALIAS VigineCrypto)

target_include_directories(VigineCrypto
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Backends are an implementation detail: linked PRIVATE so consumers inherit
# the link closure (a static lib propagates its private link deps) without
# seeing OpenSSL / BLAKE3 headers.
target_link_libraries(VigineCrypto PRIVATE vigine::openssl::ssl blake3)

# --- tests ---------------------------------------------------------------
if(VIGINECRYPTO_BUILD_TESTS)
    set(gtest_force_shared_crt ON CACHE BOOL "Use shared CRT for GoogleTest" FORCE)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/googletest ${CMAKE_BINARY_DIR}/googletest EXCLUDE_FROM_ALL)
    enable_testing()
    file(GLOB VIGINECRYPTO_TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/test/*_test.cpp)
    add_executable(viginecrypto-test ${VIGINECRYPTO_TEST_SOURCES})
    target_link_libraries(viginecrypto-test PRIVATE VigineCrypto gtest gtest_main)
    set_target_properties(viginecrypto-test PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    include(GoogleTest)
    gtest_discover_tests(viginecrypto-test DISCOVERY_TIMEOUT 60 DISCOVERY_MODE PRE_TEST)
endif()
