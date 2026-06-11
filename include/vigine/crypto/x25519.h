#pragma once

#include <array>
#include <cstddef>
#include <functional>
#include <optional>
#include <span>

namespace vigine::crypto
{

inline constexpr std::size_t kX25519PublicKeySize    = 32;
inline constexpr std::size_t kX25519PrivateKeySize   = 32;
inline constexpr std::size_t kX25519SharedSecretSize = 32;

struct X25519KeyPair;

// 32-byte X25519 public key (a Curve25519 u-coordinate). Not secret, so it is
// freely copyable.
class X25519PublicKey
{
  public:
    explicit X25519PublicKey(std::span<const std::byte, kX25519PublicKeySize> bytes);
    [[nodiscard]] std::span<const std::byte, kX25519PublicKeySize> bytes() const;

  private:
    std::array<std::byte, kX25519PublicKeySize> _bytes{};
};

// 32-byte X25519 private scalar. Move-only and zeroed on destruction; the raw
// bytes are reachable only inside withBytes, so they never survive in a copy or
// escape by pointer (mirrors Ed25519SecretKey).
class X25519SecretKey
{
  public:
    X25519SecretKey(const X25519SecretKey &)            = delete;
    X25519SecretKey &operator=(const X25519SecretKey &) = delete;
    X25519SecretKey(X25519SecretKey &&other) noexcept;
    X25519SecretKey &operator=(X25519SecretKey &&other) noexcept;
    ~X25519SecretKey();

    void withBytes(const std::function<void(std::span<const std::byte, kX25519PrivateKeySize>)> &reader) const;

  private:
    explicit X25519SecretKey(std::span<const std::byte, kX25519PrivateKeySize> scalar);

    friend struct X25519KeyPair;
    friend X25519KeyPair generateX25519KeyPair();
    friend X25519KeyPair x25519KeyPairFromScalar(std::span<const std::byte, kX25519PrivateKeySize> scalar);

    std::array<std::byte, kX25519PrivateKeySize> _bytes{};
};

struct X25519KeyPair
{
    X25519PublicKey publicKey;
    X25519SecretKey secretKey;
};

[[nodiscard]] X25519KeyPair generateX25519KeyPair();

// Deterministically rebuild a key pair from a 32-byte scalar (restored from secure
// storage, or an RFC 7748 test vector). The public key is the scalar's curve point.
[[nodiscard]] X25519KeyPair x25519KeyPairFromScalar(std::span<const std::byte, kX25519PrivateKeySize> scalar);

// X25519 ECDH: the shared secret between our secret key and a peer's public key.
// Returns nullopt when the peer key is a low-order point (OpenSSL's X25519 derive
// rejects the all-zero shared secret) -- such a contributory-behaviour failure
// MUST be rejected rather than used as a key. The peer key is wire data, so the
// whole open path is abort-free: any failure to load it or to set up the derive
// also answers nullopt.
[[nodiscard]] std::optional<std::array<std::byte, kX25519SharedSecretSize>>
    x25519SharedSecret(const X25519SecretKey &secretKey, const X25519PublicKey &peerPublicKey);

} // namespace vigine::crypto
