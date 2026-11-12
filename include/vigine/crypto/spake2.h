#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include "vigine/crypto/viginecrypto_export.h"

// SPAKE2 (RFC 9382) over P-256 with SHA-256, HKDF and HMAC: two parties that
// share a short code -- one the owner reads on one machine and types on the
// other -- each prove they know it without sending it, and both identities are
// bound into the exchange, so nobody in between can stand in for either end
// and an eavesdropper learns nothing to guess the code with offline. A code is
// meant for one attempt: a failed exchange burns it.
namespace vigine::crypto
{

inline constexpr std::size_t kSpake2ShareSize        = 65; // an uncompressed P-256 point
inline constexpr std::size_t kSpake2ScalarSize       = 32;
inline constexpr std::size_t kSpake2KeySize          = 16; // Ke
inline constexpr std::size_t kSpake2ConfirmationSize = 32; // HMAC-SHA256

// Which side of the exchange: A sends first by convention; both roles are needed.
enum class Spake2Role : std::uint8_t
{
    A,
    B,
};

/* What both sides hold when the exchange went through: the shared key and the
   confirmation each side owes the other. A side sends its own confirmation and
   accepts the peer only when the peer's matches (spake2ConfirmationsMatch). */
class Spake2Outcome
{
  public:
    Spake2Outcome(std::array<std::byte, kSpake2KeySize> sharedKey,
                  std::array<std::byte, kSpake2ConfirmationSize> confirmationA,
                  std::array<std::byte, kSpake2ConfirmationSize> confirmationB)
        : _sharedKey(sharedKey), _confirmationA(confirmationA), _confirmationB(confirmationB)
    {
    }

    [[nodiscard]] const std::array<std::byte, kSpake2KeySize> &sharedKey() const
    {
        return _sharedKey;
    }
    [[nodiscard]] const std::array<std::byte, kSpake2ConfirmationSize> &confirmationA() const
    {
        return _confirmationA;
    }
    [[nodiscard]] const std::array<std::byte, kSpake2ConfirmationSize> &confirmationB() const
    {
        return _confirmationB;
    }

  private:
    std::array<std::byte, kSpake2KeySize> _sharedKey{};
    std::array<std::byte, kSpake2ConfirmationSize> _confirmationA{};
    std::array<std::byte, kSpake2ConfirmationSize> _confirmationB{};
};

// One side of one exchange; its secret scalar is wiped when it goes.
class ISpake2Session
{
  public:
    virtual ~ISpake2Session() = default;

    // What this side sends the other: pA for A, pB for B.
    [[nodiscard]] virtual std::span<const std::byte, kSpake2ShareSize> share() const = 0;

    /* The outcome for the peer's share; nothing when it is not a point of the curve, is the
       identity, or equals this side's own share. */
    [[nodiscard]] virtual std::optional<Spake2Outcome>
    finish(std::span<const std::byte> peerShare) const = 0;
};

/* A fresh exchange: `password` is the shared scalar (spake2PasswordScalar), the identities name
   A and B as both sides know them. Nothing when the password is zero or not a scalar of the
   group. */
[[nodiscard]] VIGINECRYPTO_API std::optional<std::unique_ptr<ISpake2Session>>
beginSpake2(Spake2Role role, std::span<const std::byte> password,
            std::span<const std::byte> identityA, std::span<const std::byte> identityB);

// The same with a given secret scalar instead of a fresh one: for test vectors only.
[[nodiscard]] VIGINECRYPTO_API std::optional<std::unique_ptr<ISpake2Session>>
beginSpake2WithScalar(Spake2Role role, std::span<const std::byte> password,
                      std::span<const std::byte> identityA, std::span<const std::byte> identityB,
                      std::span<const std::byte, kSpake2ScalarSize> scalar);

/* The shared scalar for a short code: SHA-256 over `domain`, a zero byte and
   the code, reduced into the group. `domain` names what the code is for, so a
   code read for one purpose is no scalar for another. */
[[nodiscard]] VIGINECRYPTO_API std::array<std::byte, kSpake2ScalarSize> spake2PasswordScalar(std::string_view domain,
                                                                            std::string_view code);

// Two confirmations compared in constant time.
[[nodiscard]] VIGINECRYPTO_API bool
spake2ConfirmationsMatch(std::span<const std::byte, kSpake2ConfirmationSize> left,
                         std::span<const std::byte, kSpake2ConfirmationSize> right);

} // namespace vigine::crypto
