#pragma once

#include <array>
#include <cstddef>
#include <functional>
#include <optional>
#include <span>
#include <utility>
#include "vigine/crypto/viginecrypto_export.h"

namespace vigine::crypto
{

// ML-KEM-768 (FIPS 203), the key encapsulation the post-quantum half of a sealed link uses.
inline constexpr std::size_t kMlKem768PublicKeySize  = 1184;
inline constexpr std::size_t kMlKem768SecretKeySize  = 2400;
inline constexpr std::size_t kMlKem768CiphertextSize = 1088;
inline constexpr std::size_t kMlKemSharedSecretSize  = 32;

class MlKemKeyPair;

// The encapsulation key: not secret, freely copyable.
class VIGINECRYPTO_API MlKemPublicKey
{
  public:
    explicit MlKemPublicKey(std::span<const std::byte, kMlKem768PublicKeySize> bytes);
    [[nodiscard]] std::span<const std::byte, kMlKem768PublicKeySize> bytes() const;

  private:
    std::array<std::byte, kMlKem768PublicKeySize> _bytes{};
};

// The decapsulation key: move-only, zeroed on destruction, its bytes reachable only inside
// withBytes.
class VIGINECRYPTO_API MlKemSecretKey
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

class MlKemKeyPair
{
  public:
    MlKemKeyPair(MlKemPublicKey publicKey, MlKemSecretKey secretKey)
        : _publicKey(std::move(publicKey)), _secretKey(std::move(secretKey))
    {
    }

    [[nodiscard]] const MlKemPublicKey &publicKey() const { return _publicKey; }
    [[nodiscard]] const MlKemSecretKey &secretKey() const { return _secretKey; }

  private:
    MlKemPublicKey _publicKey;
    MlKemSecretKey _secretKey;
};

// What encapsulating to a peer's key gives: the ciphertext to send it, and the secret both now
// hold.
class MlKemEncapsulation
{
  public:
    MlKemEncapsulation(std::array<std::byte, kMlKem768CiphertextSize> ciphertext,
                       std::array<std::byte, kMlKemSharedSecretSize> sharedSecret)
        : _ciphertext(ciphertext), _sharedSecret(sharedSecret)
    {
    }

    [[nodiscard]] const std::array<std::byte, kMlKem768CiphertextSize> &ciphertext() const
    {
        return _ciphertext;
    }
    [[nodiscard]] const std::array<std::byte, kMlKemSharedSecretSize> &sharedSecret() const
    {
        return _sharedSecret;
    }

  private:
    std::array<std::byte, kMlKem768CiphertextSize> _ciphertext{};
    std::array<std::byte, kMlKemSharedSecretSize> _sharedSecret{};
};

[[nodiscard]] VIGINECRYPTO_API MlKemKeyPair generateMlKemKeyPair();

/* A fresh shared secret for the holder of `peerPublicKey`, and the ciphertext
   that carries it. The key comes from the wire: nothing when it is not a
   valid encapsulation key. */
[[nodiscard]] VIGINECRYPTO_API std::optional<MlKemEncapsulation>
mlKemEncapsulate(const MlKemPublicKey &peerPublicKey);

/* The shared secret `ciphertext` carries to `secretKey`. A ciphertext made for
   another key, or tampered with, yields an unrelated secret (ML-KEM's implicit
   rejection), never an error that tells the sender so; nothing only when the
   backend could not run the decapsulation. */
[[nodiscard]] VIGINECRYPTO_API std::optional<std::array<std::byte, kMlKemSharedSecretSize>>
mlKemDecapsulate(const MlKemSecretKey &secretKey,
                 std::span<const std::byte, kMlKem768CiphertextSize> ciphertext);

} // namespace vigine::crypto
