#include "cryptodetail.h"

#include "vigine/crypto/mlkem.h"

#include <algorithm>
#include <memory>
#include <openssl/crypto.h>

namespace vigine::crypto
{

using detail::fatal;
using detail::PkeyPtr;

namespace
{

using PkeyCtxPtr                 = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
constexpr const char *kAlgorithm = "ML-KEM-768";

template <std::size_t Size>
std::array<std::byte, Size> rawKey(EVP_PKEY *pkey, bool secret)
{
    std::array<std::byte, Size> bytes{};
    std::size_t length = bytes.size();
    const int read     = secret ? EVP_PKEY_get_raw_private_key(
                                      pkey, reinterpret_cast<unsigned char *>(bytes.data()), &length)
                                : EVP_PKEY_get_raw_public_key(
                                      pkey, reinterpret_cast<unsigned char *>(bytes.data()), &length);
    if (read != 1 || length != Size)
        fatal(secret ? "crypto.mlkem.export_private" : "crypto.mlkem.export_public");
    return bytes;
}

} // namespace

MlKemPublicKey::MlKemPublicKey(std::span<const std::byte, kMlKem768PublicKeySize> bytes)
{
    std::copy(bytes.begin(), bytes.end(), _bytes.begin());
}

std::span<const std::byte, kMlKem768PublicKeySize> MlKemPublicKey::bytes() const
{
    return std::span<const std::byte, kMlKem768PublicKeySize>{_bytes};
}

MlKemSecretKey::MlKemSecretKey(std::span<const std::byte, kMlKem768SecretKeySize> bytes)
{
    std::copy(bytes.begin(), bytes.end(), _bytes.begin());
}

MlKemSecretKey::MlKemSecretKey(MlKemSecretKey &&other) noexcept
{
    _bytes = other._bytes;
    OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
}

MlKemSecretKey &MlKemSecretKey::operator=(MlKemSecretKey &&other) noexcept
{
    if (this != &other)
    {
        OPENSSL_cleanse(_bytes.data(), _bytes.size());
        _bytes = other._bytes;
        OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
    }
    return *this;
}

MlKemSecretKey::~MlKemSecretKey() { OPENSSL_cleanse(_bytes.data(), _bytes.size()); }

void MlKemSecretKey::withBytes(
    const std::function<void(std::span<const std::byte, kMlKem768SecretKeySize>)> &reader) const
{
    reader(std::span<const std::byte, kMlKem768SecretKeySize>{_bytes});
}

MlKemKeyPair generateMlKemKeyPair()
{
    PkeyPtr pkey{EVP_PKEY_Q_keygen(nullptr, nullptr, kAlgorithm), &EVP_PKEY_free};
    if (!pkey)
        fatal("crypto.mlkem.keygen");
    const auto publicBytes = rawKey<kMlKem768PublicKeySize>(pkey.get(), false);
    auto secretBytes       = rawKey<kMlKem768SecretKeySize>(pkey.get(), true);
    MlKemKeyPair pair{
        MlKemPublicKey{std::span<const std::byte, kMlKem768PublicKeySize>{publicBytes}},
        MlKemSecretKey{std::span<const std::byte, kMlKem768SecretKeySize>{secretBytes}}};
    OPENSSL_cleanse(secretBytes.data(), secretBytes.size());
    return pair;
}

std::optional<MlKemEncapsulation> mlKemEncapsulate(const MlKemPublicKey &peerPublicKey)
{
    const auto peerView = peerPublicKey.bytes();
    PkeyPtr peerKey{EVP_PKEY_new_raw_public_key_ex(
                        nullptr, kAlgorithm, nullptr,
                        reinterpret_cast<const unsigned char *>(peerView.data()), peerView.size()),
                    &EVP_PKEY_free};
    // The key arrives from the wire: a failure here answers nothing rather than aborting.
    if (!peerKey)
        return std::nullopt;
    PkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, peerKey.get(), nullptr), &EVP_PKEY_CTX_free};
    MlKemEncapsulation out;
    std::size_t ciphertextLength = out.ciphertext.size();
    std::size_t secretLength     = out.sharedSecret.size();
    if (!ctx || EVP_PKEY_encapsulate_init(ctx.get(), nullptr) != 1 ||
        EVP_PKEY_encapsulate(
            ctx.get(), reinterpret_cast<unsigned char *>(out.ciphertext.data()), &ciphertextLength,
            reinterpret_cast<unsigned char *>(out.sharedSecret.data()), &secretLength) != 1 ||
        ciphertextLength != kMlKem768CiphertextSize || secretLength != kMlKemSharedSecretSize)
    {
        OPENSSL_cleanse(out.sharedSecret.data(), out.sharedSecret.size());
        return std::nullopt;
    }
    return out;
}

std::optional<std::array<std::byte, kMlKemSharedSecretSize>>
mlKemDecapsulate(const MlKemSecretKey &secretKey,
                 std::span<const std::byte, kMlKem768CiphertextSize> ciphertext)
{
    std::optional<std::array<std::byte, kMlKemSharedSecretSize>> result;
    secretKey.withBytes([&](std::span<const std::byte, kMlKem768SecretKeySize> bytes) {
        PkeyPtr ourKey{EVP_PKEY_new_raw_private_key_ex(
                           nullptr, kAlgorithm, nullptr,
                           reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size()),
                       &EVP_PKEY_free};
        if (!ourKey)
            return;
        PkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, ourKey.get(), nullptr),
                       &EVP_PKEY_CTX_free};
        std::array<std::byte, kMlKemSharedSecretSize> secret{};
        std::size_t secretLength = secret.size();
        if (ctx && EVP_PKEY_decapsulate_init(ctx.get(), nullptr) == 1 &&
            EVP_PKEY_decapsulate(ctx.get(), reinterpret_cast<unsigned char *>(secret.data()),
                                 &secretLength,
                                 reinterpret_cast<const unsigned char *>(ciphertext.data()),
                                 ciphertext.size()) == 1 &&
            secretLength == kMlKemSharedSecretSize)
            result = secret;
        OPENSSL_cleanse(secret.data(), secret.size());
    });
    return result;
}

} // namespace vigine::crypto
