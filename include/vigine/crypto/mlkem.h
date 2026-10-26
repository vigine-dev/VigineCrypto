#pragma once

#include <array>
#include <cstddef>
#include <functional>
#include <optional>
#include <span>

namespace vigine::crypto
{

// ML-KEM-768 (FIPS 203), the key encapsulation the post-quantum half of a sealed link uses.
inline constexpr std::size_t kMlKem768PublicKeySize  = 1184;
inline constexpr std::size_t kMlKem768SecretKeySize  = 2400;
inline constexpr std::size_t kMlKem768CiphertextSize = 1088;
inline constexpr std::size_t kMlKemSharedSecretSize  = 32;

struct MlKemKeyPair;

// The encapsulation key: not secret, freely copyable.
class MlKemPublicKey
{
  public:
    explicit MlKemPublicKey(std::span<const std::byte, kMlKem768PublicKeySize> bytes);
    [[nodiscard]] std::span<const std::byte, kMlKem768PublicKeySize> bytes() const;

  private:
    std::array<std::byte, kMlKem768PublicKeySize> _bytes{};
};

// The decapsulation key: move-only, zeroed on destruction, its bytes reachable only inside
// withBytes.
class MlKemSecretKey
{
  public:
    MlKemSecretKey(const MlKemSecretKey &)            = delete;
    MlKemSecretKey &operator=(const MlKemSecretKey &) = delete;
    MlKemSecretKey(MlKemSecretKey &&other) noexcept;
    MlKemSecretKey &operator=(MlKemSecretKey &&other) noexcept;
    ~MlKemSecretKey();

    void withBytes(const std::function<void(std::span<const std::byte, kMlKem768SecretKeySize>)>
                       &reader) const;

  private:
    explicit MlKemSecretKey(std::span<const std::byte, kMlKem768SecretKeySize> bytes);

    friend MlKemKeyPair generateMlKemKeyPair();

    std::array<std::byte, kMlKem768SecretKeySize> _bytes{};
};

struct MlKemKeyPair
{
    MlKemPublicKey publicKey;
    MlKemSecretKey secretKey;
};

// What encapsulating to a peer's key gives: the ciphertext to send it, and the secret both now
// hold.
struct MlKemEncapsulation
{
    std::array<std::byte, kMlKem768CiphertextSize> ciphertext{};
    std::array<std::byte, kMlKemSharedSecretSize> sharedSecret{};
};

[[nodiscard]] MlKemKeyPair generateMlKemKeyPair();

/* A fresh shared secret for the holder of `peerPublicKey`, and the ciphertext
   that carries it. The key comes from the wire: nothing when it is not a
   valid encapsulation key. */
[[nodiscard]] std::optional<MlKemEncapsulation>
mlKemEncapsulate(const MlKemPublicKey &peerPublicKey);

/* The shared secret `ciphertext` carries to `secretKey`. A ciphertext made for
   another key, or tampered with, yields an unrelated secret (ML-KEM's implicit
   rejection), never an error that tells the sender so; nothing only when the
   backend could not run the decapsulation. */
[[nodiscard]] std::optional<std::array<std::byte, kMlKemSharedSecretSize>>
mlKemDecapsulate(const MlKemSecretKey &secretKey,
                 std::span<const std::byte, kMlKem768CiphertextSize> ciphertext);

} // namespace vigine::crypto
