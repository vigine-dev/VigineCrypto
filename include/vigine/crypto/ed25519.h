#pragma once

#include <array>
#include <cstddef>
#include <functional>
#include <span>

namespace vigine::crypto
{

inline constexpr std::size_t kEd25519PublicKeySize = 32;
inline constexpr std::size_t kEd25519SeedSize      = 32;
inline constexpr std::size_t kEd25519SignatureSize = 64;

struct Ed25519KeyPair;

// 32-byte Ed25519 public key. Not secret, so it is freely copyable.
class Ed25519PublicKey
{
public:
    explicit Ed25519PublicKey(std::span<const std::byte, kEd25519PublicKeySize> bytes);
    [[nodiscard]] std::span<const std::byte, kEd25519PublicKeySize> bytes() const;

private:
    std::array<std::byte, kEd25519PublicKeySize> _bytes{};
};

// 32-byte Ed25519 private seed. Move-only and zeroed on destruction; the raw
// bytes are reachable only inside withBytes, so they never survive in a copy
// or escape by pointer.
class Ed25519SecretKey
{
public:
    Ed25519SecretKey(const Ed25519SecretKey &)            = delete;
    Ed25519SecretKey &operator=(const Ed25519SecretKey &) = delete;
    Ed25519SecretKey(Ed25519SecretKey &&other) noexcept;
    Ed25519SecretKey &operator=(Ed25519SecretKey &&other) noexcept;
    ~Ed25519SecretKey();

    void withBytes(const std::function<void(std::span<const std::byte, kEd25519SeedSize>)> &reader) const;

private:
    explicit Ed25519SecretKey(std::span<const std::byte, kEd25519SeedSize> seed);

    friend struct Ed25519KeyPair;
    friend Ed25519KeyPair generateKeyPair();

    std::array<std::byte, kEd25519SeedSize> _bytes{};
};

struct Ed25519KeyPair
{
    Ed25519PublicKey publicKey;
    Ed25519SecretKey secretKey;
};

[[nodiscard]] Ed25519KeyPair generateKeyPair();

[[nodiscard]] std::array<std::byte, kEd25519SignatureSize>
sign(const Ed25519SecretKey &secretKey, std::span<const std::byte> message);

[[nodiscard]] bool verify(const Ed25519PublicKey &publicKey, std::span<const std::byte> message,
                          std::span<const std::byte, kEd25519SignatureSize> signature);

}
