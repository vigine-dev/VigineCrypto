#pragma once

// Internal helpers shared by the OpenSSL-backed wrappers. Not installed and
// never included from a public header, so the OpenSSL types stay hidden from
// consumers of the library.

#include <openssl/evp.h>

#include <cstdio>
#include <cstdlib>
#include <memory>

namespace vigine::crypto::detail
{

[[noreturn]] inline void fatal(const char *tag)
{
    std::fprintf(stderr, "[%s] crypto backend operation failed\n", tag);
    std::abort();
}

using PkeyPtr      = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using MdCtxPtr     = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

}
