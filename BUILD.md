# Building VigineCrypto

VigineCrypto vendors and builds OpenSSL from source, so the OpenSSL build
prerequisites are ours too.

## Prerequisites

- CMake 3.24+
- A C++20 compiler (MSVC 2022+, Clang, or GCC)
- **Perl** — required by OpenSSL's `Configure`

### Windows: use a full Perl, not the Git-Bash one

The vendored OpenSSL is configured by a Perl script. It needs a *complete*
Perl distribution — [Strawberry Perl](https://strawberryperl.com) or
ActivePerl. The Perl shipped with Git for Windows / MSYS2 is missing modules
OpenSSL pulls in (`Locale::Maketext::Simple`), and the build then fails during
OpenSSL configure with a bare `exited with code 1` and no obvious cause.

Make sure a full Perl is **first on `PATH`** before configuring — this matters
even when you launch the build from a Git-Bash shell, because that shell puts
its own `perl` ahead of everything else:

```sh
export PATH="/c/Strawberry/perl/bin:$PATH"   # Git-Bash
# or open a "x64 Native Tools Command Prompt" with Strawberry Perl on PATH
```

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
```

## Test

```sh
ctest --test-dir build -C Release --output-on-failure
```
