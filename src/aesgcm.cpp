#include "vigine/crypto/aesgcm.h"

#include "cryptodetail.h"

#include "vigine/crypto/random.h"

#include <openssl/crypto.h>

#include <algorithm>

namespace vigine::crypto
{

using detail::CipherCtxPtr;
using detail::fatal;

AesGcmKey::AesGcmKey(std::span<const std::byte, kAesGcmKeySize> bytes)
{
    std::copy(bytes.begin(), bytes.end(), _bytes.begin());
}

AesGcmKey AesGcmKey::random()
{
    std::array<std::byte, kAesGcmKeySize> bytes{};
    randomBytes(bytes);
    AesGcmKey key{std::span<const std::byte, kAesGcmKeySize>{bytes}};
    OPENSSL_cleanse(bytes.data(), bytes.size());
    return key;
}

AesGcmKey::AesGcmKey(AesGcmKey &&other) noexcept
{
    _bytes = other._bytes;
    OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
}

AesGcmKey &AesGcmKey::operator=(AesGcmKey &&other) noexcept
{
    if (this != &other)
    {
        OPENSSL_cleanse(_bytes.data(), _bytes.size());
        _bytes = other._bytes;
        OPENSSL_cleanse(other._bytes.data(), other._bytes.size());
    }
    return *this;
}

AesGcmKey::~AesGcmKey()
{
    OPENSSL_cleanse(_bytes.data(), _bytes.size());
}

void AesGcmKey::withBytes(const std::function<void(std::span<const std::byte, kAesGcmKeySize>)> &reader) const
{
    reader(std::span<const std::byte, kAesGcmKeySize>{_bytes});
}

AesGcmSealed seal(const AesGcmKey &key, std::span<const std::byte, kAesGcmNonceSize> nonce,
                  std::span<const std::byte> plaintext, std::span<const std::byte> aad)
{
    AesGcmSealed sealed;
    sealed.ciphertext.resize(plaintext.size());

    key.withBytes([&](std::span<const std::byte, kAesGcmKeySize> keyBytes) {
        CipherCtxPtr ctx{EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free};
        if (!ctx
            || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1
            || EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kAesGcmNonceSize),
                                   nullptr)
                   != 1
            || EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                                  reinterpret_cast<const unsigned char *>(keyBytes.data()),
                                  reinterpret_cast<const unsigned char *>(nonce.data()))
                   != 1)
            fatal("crypto.aesgcm.seal_init");

        // The AAD update reports its own byte count, which must NOT feed the
        // ciphertext output offset (that comes only from the plaintext update);
        // otherwise an AAD-only seal would index past the ciphertext buffer.
        int aadProcessed = 0;
        if (!aad.empty()
            && EVP_EncryptUpdate(ctx.get(), nullptr, &aadProcessed,
                                 reinterpret_cast<const unsigned char *>(aad.data()),
                                 static_cast<int>(aad.size()))
                   != 1)
            fatal("crypto.aesgcm.seal_aad");

        int processed = 0;
        if (!plaintext.empty()
            && EVP_EncryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(sealed.ciphertext.data()),
                                 &processed, reinterpret_cast<const unsigned char *>(plaintext.data()),
                                 static_cast<int>(plaintext.size()))
                   != 1)
            fatal("crypto.aesgcm.seal_update");

        int finalLen = 0;
        if (EVP_EncryptFinal_ex(ctx.get(),
                                reinterpret_cast<unsigned char *>(sealed.ciphertext.data()) + processed,
                                &finalLen)
            != 1)
            fatal("crypto.aesgcm.seal_final");

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kAesGcmTagSize),
                                reinterpret_cast<unsigned char *>(sealed.tag.data()))
            != 1)
            fatal("crypto.aesgcm.seal_tag");
    });

    return sealed;
}

std::optional<std::vector<std::byte>> open(const AesGcmKey &key,
                                           std::span<const std::byte, kAesGcmNonceSize> nonce,
                                           std::span<const std::byte> ciphertext,
                                           std::span<const std::byte, kAesGcmTagSize> tag,
                                           std::span<const std::byte> aad)
{
    std::vector<std::byte> plaintext(ciphertext.size());
    bool                   authentic = false;

    key.withBytes([&](std::span<const std::byte, kAesGcmKeySize> keyBytes) {
        CipherCtxPtr ctx{EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free};
        if (!ctx
            || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1
            || EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kAesGcmNonceSize),
                                   nullptr)
                   != 1
            || EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                                  reinterpret_cast<const unsigned char *>(keyBytes.data()),
                                  reinterpret_cast<const unsigned char *>(nonce.data()))
                   != 1)
            fatal("crypto.aesgcm.open_init");

        // Separate counter for AAD so it never feeds the plaintext output
        // offset (see seal): an AAD-only open must not index past the buffer.
        int aadProcessed = 0;
        if (!aad.empty()
            && EVP_DecryptUpdate(ctx.get(), nullptr, &aadProcessed,
                                 reinterpret_cast<const unsigned char *>(aad.data()),
                                 static_cast<int>(aad.size()))
                   != 1)
            fatal("crypto.aesgcm.open_aad");

        int processed = 0;
        if (!ciphertext.empty()
            && EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(plaintext.data()), &processed,
                                 reinterpret_cast<const unsigned char *>(ciphertext.data()),
                                 static_cast<int>(ciphertext.size()))
                   != 1)
            fatal("crypto.aesgcm.open_update");

        // A non-const copy is required: the control call takes a void* tag.
        std::array<std::byte, kAesGcmTagSize> tagCopy{};
        std::copy(tag.begin(), tag.end(), tagCopy.begin());
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kAesGcmTagSize),
                                tagCopy.data())
            != 1)
            fatal("crypto.aesgcm.open_set_tag");

        int finalLen = 0;
        // DecryptFinal returns > 0 only when the tag verifies; a failure here
        // is the legitimate "tampered or wrong key" answer, not a fatal error.
        authentic = EVP_DecryptFinal_ex(ctx.get(),
                                        reinterpret_cast<unsigned char *>(plaintext.data()) + processed,
                                        &finalLen)
                    > 0;
    });

    if (!authentic)
    {
        // GCM is online: DecryptUpdate already wrote decrypted bytes before the
        // tag check failed. Never expose unauthenticated plaintext -- wipe it.
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        return std::nullopt;
    }
    return plaintext;
}

}
