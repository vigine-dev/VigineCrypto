#pragma once

#include <array>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "vigine/crypto/viginecrypto_export.h"

namespace vigine::crypto
{

inline constexpr std::size_t kAesGcmKeySize   = 32; // AES-256
inline constexpr std::size_t kAesGcmNonceSize = 12; // 96-bit GCM nonce
inline constexpr std::size_t kAesGcmTagSize   = 16; // 128-bit auth tag

// 32-byte AES-256-GCM key. Move-only and zeroed on destruction; the raw
// bytes are reachable only inside withBytes.
class VIGINECRYPTO_API AesGcmKey
{
  public:
    explicit AesGcmKey(std::span<const std::byte, kAesGcmKeySize> bytes);
    [[nodiscard]] static AesGcmKey random();

    AesGcmKey(const AesGcmKey &)            = delete;
    AesGcmKey &operator=(const AesGcmKey &) = delete;
    AesGcmKey(AesGcmKey &&other) noexcept;
    AesGcmKey &operator=(AesGcmKey &&other) noexcept;
    ~AesGcmKey();

    void
    withBytes(const std::function<void(std::span<const std::byte, kAesGcmKeySize>)> &reader) const;

  private:
    std::array<std::byte, kAesGcmKeySize> _bytes{};
};

/* One AES-256-GCM key held in its cipher contexts for as long as the object lives. It seals and
   opens into the caller's buffers -- the same bytes may be both input and output -- setting only
   the nonce per message: no allocation and no new context per message, which is what a tunnel
   needs for every frame. One object serves one thread at a time. */
class VIGINECRYPTO_API IAesGcmCipher
{
  public:
    virtual ~IAesGcmCipher() = default;

    // `out` is as long as `plaintext`.
    virtual void seal(std::span<const std::byte, kAesGcmNonceSize> nonce,
                      std::span<const std::byte> plaintext, std::span<const std::byte> aad,
                      std::span<std::byte> out, std::span<std::byte, kAesGcmTagSize> tag) = 0;
    // False, and `out` wiped, when the tag does not hold; `out` is as long as `ciphertext`.
    [[nodiscard]] virtual bool open(std::span<const std::byte, kAesGcmNonceSize> nonce,
                                    std::span<const std::byte> ciphertext,
                                    std::span<const std::byte, kAesGcmTagSize> tag,
                                    std::span<const std::byte> aad, std::span<std::byte> out) = 0;
};

[[nodiscard]] VIGINECRYPTO_API std::unique_ptr<IAesGcmCipher>
createAesGcmCipher(std::span<const std::byte, kAesGcmKeySize> key);

class AesGcmSealed
{
  public:
    AesGcmSealed() = default;
    AesGcmSealed(std::vector<std::byte> ciphertext, std::array<std::byte, kAesGcmTagSize> tag)
        : _ciphertext(std::move(ciphertext)), _tag(tag)
    {
    }

    [[nodiscard]] const std::vector<std::byte> &ciphertext() const { return _ciphertext; }
    [[nodiscard]] const std::array<std::byte, kAesGcmTagSize> &tag() const { return _tag; }

  private:
    std::vector<std::byte> _ciphertext;
    std::array<std::byte, kAesGcmTagSize> _tag{};
};

// Authenticated encryption. The caller supplies a unique nonce per key; the
// optional associated data is authenticated but not encrypted.
[[nodiscard]] VIGINECRYPTO_API AesGcmSealed seal(const AesGcmKey &key,
                                std::span<const std::byte, kAesGcmNonceSize> nonce,
                                std::span<const std::byte> plaintext,
                                std::span<const std::byte> aad = {});

// Returns the plaintext only if the tag and associated data verify; any
// tampering yields nullopt rather than forged output.
[[nodiscard]] VIGINECRYPTO_API std::optional<std::vector<std::byte>>
open(const AesGcmKey &key, std::span<const std::byte, kAesGcmNonceSize> nonce,
     std::span<const std::byte> ciphertext, std::span<const std::byte, kAesGcmTagSize> tag,
     std::span<const std::byte> aad = {});

} // namespace vigine::crypto
