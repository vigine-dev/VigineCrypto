#pragma once

// Internal helpers shared by the OpenSSL-backed wrappers. Not installed and
// never included from a public header, so the OpenSSL types stay hidden from
// consumers of the library.

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <openssl/crypto.h>
#include <openssl/evp.h>

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

// Wipes a secret's bytes when the scope ends, on every return path and when an
// exception unwinds. It holds the container by reference, so it wipes what the
// container holds at that moment. Never guard a value that is returned: the
// guard would wipe the returned object too.
template <typename Bytes>
class SecretWipe
{
public:
    explicit SecretWipe(Bytes &bytes) : _bytes{bytes} {}
    ~SecretWipe() { OPENSSL_cleanse(_bytes.data(), _bytes.size()); }

    SecretWipe(const SecretWipe &)            = delete;
    SecretWipe &operator=(const SecretWipe &) = delete;

private:
    Bytes &_bytes;
};

} // namespace vigine::crypto::detail
