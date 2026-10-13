#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

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
struct Spake2Outcome
{
    std::array<std::byte, kSpake2KeySize> sharedKey{};
    std::array<std::byte, kSpake2ConfirmationSize> confirmationA{};
    std::array<std::byte, kSpake2ConfirmationSize> confirmationB{};
};

// One side of one exchange. Move-only; its secret scalar is wiped when it goes.
class Spake2
{
  public:
    /* A fresh exchange: `password` is the shared scalar (spake2PasswordScalar),
       the identities name A and B as both sides know them. Nothing when the
       password is not a scalar of the group. */
    [[nodiscard]] static std::optional<Spake2> begin(Spake2Role role,
                                                     std::span<const std::byte> password,
                                                     std::span<const std::byte> identityA,
                                                     std::span<const std::byte> identityB);

    // The same with a given secret scalar instead of a fresh one: for test vectors only.
    [[nodiscard]] static std::optional<Spake2>
    beginWithScalar(Spake2Role role, std::span<const std::byte> password,
                    std::span<const std::byte> identityA, std::span<const std::byte> identityB,
                    std::span<const std::byte, kSpake2ScalarSize> scalar);

    // What this side sends the other: pA for A, pB for B.
    [[nodiscard]] std::span<const std::byte, kSpake2ShareSize> share() const;

    // The outcome for the peer's share; nothing when it is not a point of the curve.
    [[nodiscard]] std::optional<Spake2Outcome> finish(std::span<const std::byte> peerShare) const;

    Spake2(Spake2 &&) noexcept;
    Spake2 &operator=(Spake2 &&) noexcept;
    Spake2(const Spake2 &)            = delete;
    Spake2 &operator=(const Spake2 &) = delete;
    ~Spake2();

  private:
    struct State;
    explicit Spake2(std::unique_ptr<State> state);
    std::unique_ptr<State> _state;
};

/* The shared scalar for a short code: SHA-256 over `domain`, a zero byte and
   the code, reduced into the group. `domain` names what the code is for, so a
   code read for one purpose is no scalar for another. */
[[nodiscard]] std::array<std::byte, kSpake2ScalarSize> spake2PasswordScalar(std::string_view domain,
                                                                            std::string_view code);

// Two confirmations compared in constant time.
[[nodiscard]] bool
spake2ConfirmationsMatch(std::span<const std::byte, kSpake2ConfirmationSize> left,
                         std::span<const std::byte, kSpake2ConfirmationSize> right);

} // namespace vigine::crypto
