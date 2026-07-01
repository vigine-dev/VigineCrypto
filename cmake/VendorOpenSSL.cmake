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

# OpenSSL's Perl/make build resolves its C compiler from `$CC`, falling
# back to a bare `gcc`/`cc` found on PATH. When that PATH default is not
# the toolchain CMake selected for the rest of the project, libcrypto is
# compiled against a different compiler's system headers and can emit
# references to glibc symbols the final link target never provides (e.g.
# `__pthread_cond_timedwait64` from a stray time64 redirect). Pin the
# OpenSSL build to ${CMAKE_C_COMPILER} so a single toolchain compiles the
# whole project. On Windows the env wrapper stays empty -- the VC build
# already drives `cl` directly and does not consult `$CC`.
if(WIN32)
    set(_openssl_crypto_lib ${_openssl_install}/lib/libcrypto.lib)
    set(_openssl_ssl_lib ${_openssl_install}/lib/libssl.lib)
    set(_openssl_build_cmd nmake)
    set(_openssl_install_cmd nmake install_dev)
    # libcrypto (CAPI engine, winstore store) and libssl reference Windows
    # system import libraries not bundled into the static .lib.
    set(_openssl_syslibs ws2_32 crypt32 advapi32 user32 gdi32 bcrypt)
    set(_openssl_toolchain_env "")
else()
    set(_openssl_crypto_lib ${_openssl_install}/lib/libcrypto.a)
    set(_openssl_ssl_lib ${_openssl_install}/lib/libssl.a)
    set(_openssl_build_cmd make -j${_openssl_jobs} build_libs)
    set(_openssl_install_cmd make install_dev)
    set(_openssl_syslibs "")
    set(_openssl_toolchain_env ${CMAKE_COMMAND} -E env "CC=${CMAKE_C_COMPILER}")
endif()

# Out-of-source build keeps the submodule working tree clean -- but OpenSSL
# 3.5.x's out-of-tree build is broken on Windows: Configure mkpath's the
# build.info "incdir|module" generator paths literally (`util\perl|OpenSSL\...`
# -> "Invalid argument"), the provider DER perl modules are not found during
# code generation, and some exporter GENERATE rules (OpenSSLConfig.cmake) are
# dropped from the generated makefile. All three vanish when OpenSSL is built
# IN-TREE (build dir == source dir), which is OpenSSL's common Windows path.
# So on Windows we build in-tree in a PRIVATE COPY of the source (the submodule
# working tree stays clean); on Unix/macOS the out-of-source build is fine.
if(WIN32)
    set(_openssl_workdir ${_openssl_prefix}/src)
    set(_openssl_source_dir ${_openssl_workdir})
    set(_openssl_configure_dir ${_openssl_workdir})
    set(_openssl_download_cmd ${CMAKE_COMMAND} -E copy_directory ${_openssl_src} ${_openssl_workdir})
    # In-tree build: BUILD_IN_SOURCE 1 and NO BINARY_DIR (CMake rejects both).
    set(_openssl_dir_args BUILD_IN_SOURCE 1)
    # The "legacy" provider (deprecated MD2/RC4/DES/Blowfish/IDEA/... algorithms
    # the engine never uses -- it needs only the modern default provider: AES-GCM,
    # SHA-2, Ed25519, X25519, HKDF) is the only loadable-module DLL a no-shared
    # build still emits. That DLL fails to link under the CMake-driven nmake step
    # (the MSBuild custom-command environment lacks the CRT import libs / applink
    # uplink table a standalone VC shell provides). We never load a deprecated
    # provider, so disable it on Windows -- the build then emits only static libs.
    set(_openssl_extra_conf no-legacy)
else()
    set(_openssl_source_dir ${_openssl_src})
    set(_openssl_configure_dir ${_openssl_src})
    set(_openssl_download_cmd "")
    set(_openssl_dir_args BINARY_DIR ${_openssl_prefix}/build BUILD_IN_SOURCE 0)
    set(_openssl_extra_conf "")
endif()

ExternalProject_Add(openssl_external
    SOURCE_DIR ${_openssl_source_dir}
    PREFIX ${_openssl_prefix}
    ${_openssl_dir_args}
    DOWNLOAD_COMMAND ${_openssl_download_cmd}
    UPDATE_COMMAND ""
    # `--libdir=lib` pins the install layout on every distro: OpenSSL's
    # default puts archives into `lib64` on 64-bit Linux, but the
    # IMPORTED file paths we hand back to consumers below use the
    # plain `lib` shape across all OSes. Without this flag a Linux
    # rebuild silently installs into `install/lib64/lib{ssl,crypto}.a`
    # and Make then fails to find `install/lib/lib{ssl,crypto}.a`
    # during the consumer link step with `No rule to make target`.
    # `perl` must resolve to a full Perl (Strawberry or ActivePerl on Windows).
    # The MSYS / Git-Bash perl lacks Locale::Maketext::Simple, which Configure
    # pulls in transitively, so a build launched from a Git-Bash shell dies at
    # configure with a bare "exited with code 1". Put a full Perl first on PATH.
    CONFIGURE_COMMAND ${_openssl_toolchain_env} perl ${_openssl_configure_dir}/Configure ${_openssl_target}
        no-shared no-apps no-tests no-docs ${_openssl_extra_conf}
        --prefix=${_openssl_install} --libdir=lib
        --openssldir=${_openssl_install}/ssl
    BUILD_COMMAND ${_openssl_toolchain_env} ${_openssl_build_cmd}
    INSTALL_COMMAND ${_openssl_toolchain_env} ${_openssl_install_cmd}
    BUILD_BYPRODUCTS ${_openssl_crypto_lib} ${_openssl_ssl_lib}
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
target_link_libraries(vigine_openssl_crypto INTERFACE ${_openssl_crypto_lib} ${CMAKE_DL_LIBS} Threads::Threads ${_openssl_syslibs})
add_library(vigine::openssl::crypto ALIAS vigine_openssl_crypto)

# libssl (TLS). libssl must precede libcrypto on the link line.
add_library(vigine_openssl_ssl INTERFACE)
add_dependencies(vigine_openssl_ssl openssl_external)
target_include_directories(vigine_openssl_ssl INTERFACE ${_openssl_install}/include)
target_link_libraries(vigine_openssl_ssl INTERFACE ${_openssl_ssl_lib} ${_openssl_crypto_lib} ${CMAKE_DL_LIBS} Threads::Threads ${_openssl_syslibs})
add_library(vigine::openssl::ssl ALIAS vigine_openssl_ssl)
