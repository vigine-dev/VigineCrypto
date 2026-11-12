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

# --- the library ---------------------------------------------------------
# VigineCrypto is a shared library: it exports only its own interfaces,
# factories, key and value types (marked VIGINECRYPTO_API). OpenSSL and BLAKE3
# are static archives linked inside and none of their symbols leave the library.
file(GLOB VIGINECRYPTO_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
file(GLOB VIGINECRYPTO_HEADERS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/include/vigine/crypto/*.h)

set(VIGINECRYPTO_GENERATED_INCLUDE ${CMAKE_CURRENT_BINARY_DIR}/generated)
add_library(VigineCrypto SHARED ${VIGINECRYPTO_SOURCES} ${VIGINECRYPTO_HEADERS})
add_library(VigineCrypto::VigineCrypto ALIAS VigineCrypto)

include(GenerateExportHeader)
generate_export_header(VigineCrypto
    BASE_NAME VIGINECRYPTO
    EXPORT_MACRO_NAME VIGINECRYPTO_API
    EXPORT_FILE_NAME ${VIGINECRYPTO_GENERATED_INCLUDE}/vigine/crypto/viginecrypto_export.h)

# Visibility, stated for every system rather than left to the defaults:
#  - hidden by default for C and C++ (a symbol is exported only when marked VIGINECRYPTO_API);
#  - inline member functions hidden as well;
#  - on Windows nothing is exported unless dllexport-marked (no export-all).
set_target_properties(VigineCrypto PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    WINDOWS_EXPORT_ALL_SYMBOLS OFF
    POSITION_INDEPENDENT_CODE ON)
set_target_properties(blake3 PROPERTIES POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
# A private STL member in an exported class is intended: the data is not part of the ABI contract.
if(MSVC)
    target_compile_options(VigineCrypto PUBLIC /wd4251)
endif()

target_include_directories(VigineCrypto
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PUBLIC $<BUILD_INTERFACE:${VIGINECRYPTO_GENERATED_INCLUDE}>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# The backends are static archives linked PRIVATE: consumers see neither their headers nor
# their symbols.
target_link_libraries(VigineCrypto PRIVATE vigine::openssl::ssl blake3)

# What may leave the library, per system:
#  - macOS: -load_hidden pulls each archive in with every symbol private, and an exported-symbols
#    list (written into the build folder, the same names as the Linux version script) names the
#    only symbols exported; -dead_strip drops the rest;
#  - Linux: --exclude-libs,ALL keeps the archives' symbols out of the dynamic table, and a version
#    script exports only vigine::* (the standard library's weak instantiations stay private too);
#  - Windows: a DLL exports only dllexport-marked symbols, so the archives link in as they are;
#    /OPT:REF drops the unreferenced.
if(APPLE)
    set(VIGINECRYPTO_EXPORTS_FILE ${CMAKE_CURRENT_BINARY_DIR}/viginecrypto.exp)
    file(WRITE ${VIGINECRYPTO_EXPORTS_FILE}
"__ZN6vigine*
__ZNK6vigine*
__ZNO6vigine*
__ZNKO6vigine*
__ZTVN6vigine*
__ZTIN6vigine*
__ZTSN6vigine*
")
    target_link_options(VigineCrypto PRIVATE
        "LINKER:-exported_symbols_list,${VIGINECRYPTO_EXPORTS_FILE}"
        "LINKER:-dead_strip"
        "LINKER:-load_hidden,$<TARGET_FILE:blake3>")
    if(NOT VIGINECRYPTO_SYSTEM_OPENSSL)
        target_link_options(VigineCrypto PRIVATE
            "LINKER:-load_hidden,${_openssl_ssl_lib}"
            "LINKER:-load_hidden,${_openssl_crypto_lib}")
    endif()
    set_property(TARGET VigineCrypto APPEND PROPERTY LINK_DEPENDS ${VIGINECRYPTO_EXPORTS_FILE})
elseif(UNIX)
    target_link_options(VigineCrypto PRIVATE
        "LINKER:--exclude-libs,ALL"
        "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/cmake/viginecrypto.map")
    set_property(TARGET VigineCrypto APPEND PROPERTY LINK_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/viginecrypto.map)
else()
    target_link_options(VigineCrypto PRIVATE "LINKER:/OPT:REF")
endif()

# --- tests ---------------------------------------------------------------
# VigineUnitTest is found from CMAKE_PREFIX_PATH (<root>/install/<variant>).
if(VIGINECRYPTO_BUILD_TESTS)
    enable_testing()
    find_package(VigineUnitTest REQUIRED)
    vigine_unit_add_tests(viginecrypto-test SOURCES
        test/aesgcm_test.cpp
        test/compare_test.cpp
        test/cryptodetail_test.cpp
        test/ed25519_test.cpp
        test/hash_test.cpp
        test/hkdf_test.cpp
        test/mlkem_test.cpp
        test/random_test.cpp
        test/spake2_test.cpp
        test/tls_test.cpp
        test/x25519_test.cpp)
    # cryptodetail_test and tls_test use OpenSSL directly.
    target_link_libraries(viginecrypto-test PRIVATE VigineCrypto::VigineCrypto vigine::openssl::ssl)
endif()
