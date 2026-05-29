# Builds libcrypto from the pinned external/openssl submodule and exposes
# it as vigine::openssl::crypto. The OpenSSL build system is Perl + make,
# not CMake, so it is driven through ExternalProject. libssl (TLS) is wired
# separately; this module links libcrypto only.

include(ExternalProject)
include(ProcessorCount)

# libcrypto consumers need pthread (and dl on Linux). Find the Threads target
# here so this module does not depend on inclusion order.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(_openssl_src ${VIGINECRYPTO_ROOT_DIR}/external/openssl)
set(_openssl_prefix ${CMAKE_BINARY_DIR}/external/openssl)
set(_openssl_install ${_openssl_prefix}/install)

ProcessorCount(_openssl_jobs)
if(_openssl_jobs EQUAL 0)
    set(_openssl_jobs 4)
endif()

# OpenSSL's Configure needs an explicit platform/arch triple.
if(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(_openssl_target darwin64-arm64-cc)
    else()
        set(_openssl_target darwin64-x86_64-cc)
    endif()
elseif(WIN32)
    set(_openssl_target VC-WIN64A)
elseif(UNIX)
    set(_openssl_target linux-x86_64)
else()
    message(FATAL_ERROR "VendorOpenSSL: no OpenSSL Configure target for this platform")
endif()

if(WIN32)
    set(_openssl_crypto_lib ${_openssl_install}/lib/libcrypto.lib)
    set(_openssl_build_cmd nmake)
    set(_openssl_install_cmd nmake install_dev)
else()
    set(_openssl_crypto_lib ${_openssl_install}/lib/libcrypto.a)
    set(_openssl_build_cmd make -j${_openssl_jobs} build_libs)
    set(_openssl_install_cmd make install_dev)
endif()

# Out-of-source build keeps the submodule working tree clean.
ExternalProject_Add(openssl_external
    SOURCE_DIR ${_openssl_src}
    PREFIX ${_openssl_prefix}
    BINARY_DIR ${_openssl_prefix}/build
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    CONFIGURE_COMMAND perl ${_openssl_src}/Configure ${_openssl_target}
        no-shared no-apps no-tests no-docs
        --prefix=${_openssl_install} --openssldir=${_openssl_install}/ssl
    BUILD_COMMAND ${_openssl_build_cmd}
    INSTALL_COMMAND ${_openssl_install_cmd}
    BUILD_BYPRODUCTS ${_openssl_crypto_lib}
    BUILD_IN_SOURCE 0
    LOG_CONFIGURE 1
    LOG_BUILD 1
    LOG_INSTALL 1
)

file(MAKE_DIRECTORY ${_openssl_install}/include)

# add_dependencies() is rejected on IMPORTED targets, so the build-order link
# to the ExternalProject is carried by an INTERFACE wrapper consumers link.
add_library(vigine_openssl_crypto INTERFACE)
add_dependencies(vigine_openssl_crypto openssl_external)
target_include_directories(vigine_openssl_crypto INTERFACE ${_openssl_install}/include)
target_link_libraries(vigine_openssl_crypto INTERFACE ${_openssl_crypto_lib} ${CMAKE_DL_LIBS} Threads::Threads)
add_library(vigine::openssl::crypto ALIAS vigine_openssl_crypto)
