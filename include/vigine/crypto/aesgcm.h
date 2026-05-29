#pragma once

#include <array>
#include <cstddef>
#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace vigine::crypto
{

inline constexpr std::size_t kAesGcmKeySize   = 32; // AES-256
inline constexpr std::size_t kAesGcmNonceSize = 12; // 96-bit GCM nonce
inline constexpr std::size_t kAesGcmTagSize   = 16; // 128-bit auth tag

// 32-byte AES-256-GCM key. Move-only and zeroed on destruction; the raw
// bytes are reachable only inside withBytes.
class AesGcmKey
{
public:
    explicit AesGcmKey(std::span<const std::byte, kAesGcmKeySize> bytes);
    [[nodiscard]] static AesGcmKey random();

    AesGcmKey(const AesGcmKey &)            = delete;
    AesGcmKey &operator=(const AesGcmKey &) = delete;
    AesGcmKey(AesGcmKey &&other) noexcept;
    AesGcmKey &operator=(AesGcmKey &&other) noexcept;
    ~AesGcmKey();

    void withBytes(const std::function<void(std::span<const std::byte, kAesGcmKeySize>)> &reader) const;

private:
    std::array<std::byte, kAesGcmKeySize> _bytes{};
};

struct AesGcmSealed
{
    std::vector<std::byte>                ciphertext;
    std::array<std::byte, kAesGcmTagSize> tag{};
};

// Authenticated encryption. The caller supplies a unique nonce per key; the
// optional associated data is authenticated but not encrypted.
[[nodiscard]] AesGcmSealed seal(const AesGcmKey &key, std::span<const std::byte, kAesGcmNonceSize> nonce,
                                std::span<const std::byte> plaintext, std::span<const std::byte> aad = {});

// Returns the plaintext only if the tag and associated data verify; any
// tampering yields nullopt rather than forged output.
[[nodiscard]] std::optional<std::vector<std::byte>>
open(const AesGcmKey &key, std::span<const std::byte, kAesGcmNonceSize> nonce,
     std::span<const std::byte> ciphertext, std::span<const std::byte, kAesGcmTagSize> tag,
     std::span<const std::byte> aad = {});

}
