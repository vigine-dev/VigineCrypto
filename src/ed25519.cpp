#include "vigine/crypto/ed25519.h"

#include "cryptodetail.h"

#include <openssl/crypto.h>

#include <algorithm>

namespace vigine::crypto
{

using detail::fatal;
using detail::MdCtxPtr;
using detail::PkeyPtr;

Ed25519PublicKey::Ed25519PublicKey(std::span<const std::byte, kEd25519PublicKeySize> bytes)
{
    std::copy(bytes.begin(), bytes.end(), _bytes.begin());
}

std::span<const std::byte, kEd25519PublicKeySize> Ed25519PublicKey::bytes() const
{
    return std::span<const std::byte, kEd25519PublicKeySize>{_bytes};
}

Ed25519SecretKey::Ed25519SecretKey(std::span<const std::byte, kEd25519SeedSize> seed)
{
    std::copy(seed.begin(), seed.end(), _bytes.begin());
}

Ed25519SecretKey::Ed25519SecretKey(Ed25519SecretKey &&other) noexcept
{
    _bytes = other._bytes;
    OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
}

Ed25519SecretKey &Ed25519SecretKey::operator=(Ed25519SecretKey &&other) noexcept
{
    if (this != &other)
    {
        OPENSSL_cleanse(_bytes.data(), _bytes.size());
        _bytes = other._bytes;
        OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
    }
    return *this;
}

Ed25519SecretKey::~Ed25519SecretKey()
{
    OPENSSL_cleanse(_bytes.data(), _bytes.size());
}

void Ed25519SecretKey::withBytes(
    const std::function<void(std::span<const std::byte, kEd25519SeedSize>)> &reader) const
{
    reader(std::span<const std::byte, kEd25519SeedSize>{_bytes});
}

Ed25519KeyPair generateKeyPair()
{
    PkeyPtr pkey{EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), &EVP_PKEY_free};
    if (!pkey)
        fatal("crypto.ed25519.keygen");

    std::array<std::byte, kEd25519PublicKeySize> publicBytes{};
    std::array<std::byte, kEd25519SeedSize>      seedBytes{};
    std::size_t                                  publicLen = publicBytes.size();
    std::size_t                                  seedLen   = seedBytes.size();

    if (EVP_PKEY_get_raw_public_key(pkey.get(), reinterpret_cast<unsigned char *>(publicBytes.data()),
                                    &publicLen) != 1
        || publicLen != kEd25519PublicKeySize)
        fatal("crypto.ed25519.export_public");
    if (EVP_PKEY_get_raw_private_key(pkey.get(), reinterpret_cast<unsigned char *>(seedBytes.data()),
                                     &seedLen) != 1
        || seedLen != kEd25519SeedSize)
        fatal("crypto.ed25519.export_private");

    Ed25519KeyPair pair{Ed25519PublicKey{std::span<const std::byte, kEd25519PublicKeySize>{publicBytes}},
                        Ed25519SecretKey{std::span<const std::byte, kEd25519SeedSize>{seedBytes}}};
    OPENSSL_cleanse(seedBytes.data(), seedBytes.size());
    return pair;
}

Ed25519KeyPair keyPairFromSeed(std::span<const std::byte, kEd25519SeedSize> seed)
{
    PkeyPtr pkey{EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                              reinterpret_cast<const unsigned char *>(seed.data()),
                                              seed.size()),
                 &EVP_PKEY_free};
    if (!pkey)
        fatal("crypto.ed25519.load_seed");

    std::array<std::byte, kEd25519PublicKeySize> publicBytes{};
    std::size_t                                  publicLen = publicBytes.size();
    if (EVP_PKEY_get_raw_public_key(pkey.get(), reinterpret_cast<unsigned char *>(publicBytes.data()),
                                    &publicLen) != 1
        || publicLen != kEd25519PublicKeySize)
        fatal("crypto.ed25519.derive_public");

    return Ed25519KeyPair{
        Ed25519PublicKey{std::span<const std::byte, kEd25519PublicKeySize>{publicBytes}},
        Ed25519SecretKey{seed}};
}

std::array<std::byte, kEd25519SignatureSize> sign(const Ed25519SecretKey &secretKey,
                                                  std::span<const std::byte> message)
{
    std::array<std::byte, kEd25519SignatureSize> signature{};
    secretKey.withBytes([&](std::span<const std::byte, kEd25519SeedSize> seed) {
        PkeyPtr pkey{EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                  reinterpret_cast<const unsigned char *>(seed.data()),
                                                  seed.size()),
                     &EVP_PKEY_free};
        if (!pkey)
            fatal("crypto.ed25519.load_private");
        MdCtxPtr ctx{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
        if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1)
            fatal("crypto.ed25519.sign_init");
        std::size_t signatureLen = signature.size();
        if (EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char *>(signature.data()), &signatureLen,
                           reinterpret_cast<const unsigned char *>(message.data()), message.size()) != 1
            || signatureLen != kEd25519SignatureSize)
            fatal("crypto.ed25519.sign");
    });
    return signature;
}

bool verify(const Ed25519PublicKey &publicKey, std::span<const std::byte> message,
            std::span<const std::byte, kEd25519SignatureSize> signature)
{
    const auto publicBytes = publicKey.bytes();
    PkeyPtr    pkey{EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                reinterpret_cast<const unsigned char *>(publicBytes.data()),
                                                publicBytes.size()),
                    &EVP_PKEY_free};
    if (!pkey)
        fatal("crypto.ed25519.load_public");
    MdCtxPtr ctx{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1)
        fatal("crypto.ed25519.verify_init");
    const int result =
        EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char *>(signature.data()),
                         signature.size(), reinterpret_cast<const unsigned char *>(message.data()),
                         message.size());
    return result == 1;
}

}
