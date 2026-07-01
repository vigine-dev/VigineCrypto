#include "vigine/crypto/x25519.h"

#include "cryptodetail.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <cstdint>
#include <memory>

namespace vigine::crypto
{

using detail::fatal;
using detail::PkeyPtr;

namespace
{
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

PkeyPtr loadPrivate(std::span<const std::byte, kX25519PrivateKeySize> scalar)
{
    PkeyPtr pkey{EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                              reinterpret_cast<const unsigned char *>(scalar.data()),
                                              scalar.size()),
                 &EVP_PKEY_free};
    if (!pkey)
        fatal("crypto.x25519.load_private");
    return pkey;
}

std::array<std::byte, kX25519PublicKeySize> publicKeyOf(EVP_PKEY *pkey)
{
    std::array<std::byte, kX25519PublicKeySize> publicBytes{};
    std::size_t                                 publicLen = publicBytes.size();
    if (EVP_PKEY_get_raw_public_key(pkey, reinterpret_cast<unsigned char *>(publicBytes.data()),
                                    &publicLen) != 1
        || publicLen != kX25519PublicKeySize)
        fatal("crypto.x25519.export_public");
    return publicBytes;
}
} // namespace

X25519PublicKey::X25519PublicKey(std::span<const std::byte, kX25519PublicKeySize> bytes)
{
    std::copy(bytes.begin(), bytes.end(), _bytes.begin());
}

std::span<const std::byte, kX25519PublicKeySize> X25519PublicKey::bytes() const
{
    return std::span<const std::byte, kX25519PublicKeySize>{_bytes};
}

X25519SecretKey::X25519SecretKey(std::span<const std::byte, kX25519PrivateKeySize> scalar)
{
    std::copy(scalar.begin(), scalar.end(), _bytes.begin());
}

X25519SecretKey::X25519SecretKey(X25519SecretKey &&other) noexcept
{
    _bytes = other._bytes;
    OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
}

X25519SecretKey &X25519SecretKey::operator=(X25519SecretKey &&other) noexcept
{
    if (this != &other)
    {
        OPENSSL_cleanse(_bytes.data(), _bytes.size());
        _bytes = other._bytes;
        OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
    }
    return *this;
}

X25519SecretKey::~X25519SecretKey()
{
    OPENSSL_cleanse(_bytes.data(), _bytes.size());
}

void X25519SecretKey::withBytes(
    const std::function<void(std::span<const std::byte, kX25519PrivateKeySize>)> &reader) const
{
    reader(std::span<const std::byte, kX25519PrivateKeySize>{_bytes});
}

X25519KeyPair generateX25519KeyPair()
{
    PkeyPtr pkey{EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519"), &EVP_PKEY_free};
    if (!pkey)
        fatal("crypto.x25519.keygen");

    const std::array<std::byte, kX25519PublicKeySize> publicBytes = publicKeyOf(pkey.get());
    std::array<std::byte, kX25519PrivateKeySize>      privateBytes{};
    std::size_t                                       privateLen = privateBytes.size();
    if (EVP_PKEY_get_raw_private_key(pkey.get(), reinterpret_cast<unsigned char *>(privateBytes.data()),
                                     &privateLen) != 1
        || privateLen != kX25519PrivateKeySize)
        fatal("crypto.x25519.export_private");

    X25519KeyPair pair{X25519PublicKey{std::span<const std::byte, kX25519PublicKeySize>{publicBytes}},
                       X25519SecretKey{std::span<const std::byte, kX25519PrivateKeySize>{privateBytes}}};
    OPENSSL_cleanse(privateBytes.data(), privateBytes.size());
    return pair;
}

X25519KeyPair x25519KeyPairFromScalar(std::span<const std::byte, kX25519PrivateKeySize> scalar)
{
    PkeyPtr                                           pkey        = loadPrivate(scalar);
    const std::array<std::byte, kX25519PublicKeySize> publicBytes = publicKeyOf(pkey.get());
    return X25519KeyPair{X25519PublicKey{std::span<const std::byte, kX25519PublicKeySize>{publicBytes}},
                         X25519SecretKey{scalar}};
}

std::optional<std::array<std::byte, kX25519SharedSecretSize>>
    x25519SharedSecret(const X25519SecretKey &secretKey, const X25519PublicKey &peerPublicKey)
{
    std::optional<std::array<std::byte, kX25519SharedSecretSize>> result;
    secretKey.withBytes(
        [&](std::span<const std::byte, kX25519PrivateKeySize> scalar)
        {
            PkeyPtr    ourKey   = loadPrivate(scalar);
            const auto peerView = peerPublicKey.bytes();
            PkeyPtr    peerKey{EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                           reinterpret_cast<const unsigned char *>(peerView.data()),
                                                           peerView.size()),
                            &EVP_PKEY_free};
            // The peer key arrives from the wire: every failure on this open
            // path answers nullopt instead of aborting, so hostile or
            // malformed input can never take the process down.
            if (!peerKey)
                return;

            PkeyCtxPtr ctx{EVP_PKEY_CTX_new(ourKey.get(), nullptr), &EVP_PKEY_CTX_free};
            if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1
                || EVP_PKEY_derive_set_peer(ctx.get(), peerKey.get()) != 1)
                return;

            std::array<std::byte, kX25519SharedSecretSize> shared{};
            std::size_t                                    sharedLen = shared.size();
            // A low-order peer point makes OpenSSL's X25519 derive return 0 (the
            // all-zero shared secret is rejected at the source), so a failure here
            // is exactly the contributory-behaviour check -- surface it as nullopt.
            const int derived = EVP_PKEY_derive(ctx.get(), reinterpret_cast<unsigned char *>(shared.data()),
                                                &sharedLen);
            if (derived == 1 && sharedLen == kX25519SharedSecretSize)
                result = shared;
            else
                OPENSSL_cleanse(shared.data(), shared.size());
        });
    return result;
}

} // namespace vigine::crypto
