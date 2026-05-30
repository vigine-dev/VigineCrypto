#include "vigine/crypto/hkdf.h"

#include "cryptodetail.h"

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <cstddef>
#include <memory>

namespace vigine::crypto
{

using detail::fatal;

namespace
{
using KdfPtr    = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
using KdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;
} // namespace

std::vector<std::byte> hkdfSha256(std::span<const std::byte> secret, std::span<const std::byte> salt,
                                  std::span<const std::byte> info, std::size_t outLength)
{
    if (outLength == 0)
        return {};

    KdfPtr kdf{EVP_KDF_fetch(nullptr, "HKDF", nullptr), &EVP_KDF_free};
    if (!kdf)
        fatal("crypto.hkdf.fetch");
    KdfCtxPtr ctx{EVP_KDF_CTX_new(kdf.get()), &EVP_KDF_CTX_free};
    if (!ctx)
        fatal("crypto.hkdf.ctx");

    char       digest[] = "SHA256";
    OSSL_PARAM params[5];
    std::size_t index   = 0;
    params[index++]     = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    params[index++]     = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<std::byte *>(secret.data()), secret.size());
    if (!salt.empty())
        params[index++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                            const_cast<std::byte *>(salt.data()), salt.size());
    if (!info.empty())
        params[index++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                            const_cast<std::byte *>(info.data()), info.size());
    params[index++] = OSSL_PARAM_construct_end();

    std::vector<std::byte> out(outLength);
    // EVP_KDF_derive returns 0 when outLength exceeds HKDF's 255*HashLen ceiling
    // (8160 for SHA-256), so an over-long request surfaces as an empty result.
    if (EVP_KDF_derive(ctx.get(), reinterpret_cast<unsigned char *>(out.data()), outLength, params) != 1)
        return {};
    return out;
}

} // namespace vigine::crypto
