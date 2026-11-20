# Building VigineCrypto

VigineCrypto vendors and builds OpenSSL from source, so the OpenSSL build
prerequisites are ours too.

## Build by the recipe

`vigine.build.toml` is the recipe: variants debug and release, the settings, and the configure, build and test
steps. The VigineBuild tool runs it (`build_recipe.py validate vigine.build.toml` checks it); the settings it passes
are the ones below.

## Prerequisites

- CMake 3.25+ and Ninja
- A C++23 compiler (our clang)
- **Perl and make**, named explicitly. OpenSSL is built by its own `Configure` and make, and the configure
  never searches `PATH` for them. Pass both as absolute paths:
  - `VIGINECRYPTO_PERL` -- the Perl that runs OpenSSL's `Configure`;
  - `VIGINECRYPTO_MAKE` -- `make` on macOS and Linux, `nmake` of the Visual Studio toolchain on Windows.

  When one is missing or does not exist the configure stops and names it. The recipe states them per system:
  macOS and Ubuntu `/usr/bin/perl` and `/usr/bin/make`; Windows `C:/Strawberry/perl/bin/perl.exe` and the `nmake.exe`
  under `VC/Tools/MSVC/<version>/bin/Hostx64/x64` of Visual Studio.

### Windows: use a full Perl, not the Git-Bash one

OpenSSL's `Configure` needs a *complete* Perl -- [Strawberry Perl](https://strawberryperl.com) or ActivePerl. The Perl
of Git for Windows / MSYS2 lacks modules OpenSSL pulls in (`Locale::Maketext::Simple`) and the configure dies with a
bare `exited with code 1`. Point `VIGINECRYPTO_PERL` at Strawberry's `perl.exe`, and configure from a Visual Studio
developer prompt (`vcvars64.bat`) so `nmake` finds `INCLUDE` and `LIB`.

### A system OpenSSL instead

Where Perl cannot be made whole -- a container whose distribution splits Perl
into modules it did not install -- but the system ships OpenSSL 3.5 with its
headers, link that one and build no OpenSSL at all:

```sh
cmake -S . -B build -DVIGINECRYPTO_SYSTEM_OPENSSL=ON
```

### OpenSSL lives in the build folder

OpenSSL is built once, inside VigineCrypto's own build folder. No copy of it is shared between build trees or kept elsewhere on the machine.

## Build

```sh
cmake -S . -B build/debug -G Ninja -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_PREFIX_PATH=<root>/install/debug \
    -DVIGINECRYPTO_PERL=/usr/bin/perl -DVIGINECRYPTO_MAKE=/usr/bin/make
cmake --build build/debug
```

## Test

```sh
ctest --test-dir build/debug --output-on-failure
```

VigineCrypto's tests run on VigineUnitTest, found from `CMAKE_PREFIX_PATH`.

## Install and use

```sh
cmake --install build/debug --prefix <prefix>
```

installs VigineCrypto's own headers and `viginecrypto_export.h` into `include/vigine/crypto`, the shared library, and
the package files in `lib/cmake/VigineCrypto`. No OpenSSL or BLAKE3 header or library is installed; they live inside
the shared library. A consumer uses `find_package(VigineCrypto)` and `VigineCrypto::VigineCrypto`.
