#include "vigine/crypto/x25519.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <span>
#include <string_view>
#include <vector>

using namespace vigine::crypto;

namespace
{
std::array<std::byte, 32> fromHex32(std::string_view hex)
{
    auto nibble = [](char character) -> int {
        if (character >= '0' && character <= '9')
            return character - '0';
        return (character - 'a') + 10;
    };
    std::array<std::byte, 32> out{};
    for (std::size_t index = 0; index < 32; ++index)
        out[index] =
            static_cast<std::byte>((nibble(hex[index * 2]) << 4) | nibble(hex[index * 2 + 1]));
    return out;
}

// RFC 7748 section 6.1 -- the X25519 Diffie-Hellman test vector.
constexpr std::string_view kAlicePrivate =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
constexpr std::string_view kAlicePublic =
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
constexpr std::string_view kBobPrivate =
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
constexpr std::string_view kBobPublic =
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
constexpr std::string_view kSharedSecret =
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
} // namespace

TEST(X25519, DerivesPublicKeyFromScalarPerRfc7748)
{
    const std::array<std::byte, 32> alicePrivate = fromHex32(kAlicePrivate);
    const X25519KeyPair alice =
        x25519KeyPairFromScalar(std::span<const std::byte, 32>(alicePrivate));
    const std::array<std::byte, 32> aliceExpected = fromHex32(kAlicePublic);
    const auto aliceDerived                       = alice.publicKey.bytes();
    EXPECT_TRUE(std::equal(aliceDerived.begin(), aliceDerived.end(), aliceExpected.begin()));

    const std::array<std::byte, 32> bobPrivate = fromHex32(kBobPrivate);
    const X25519KeyPair bob = x25519KeyPairFromScalar(std::span<const std::byte, 32>(bobPrivate));
    const std::array<std::byte, 32> bobExpected = fromHex32(kBobPublic);
    const auto bobDerived                       = bob.publicKey.bytes();
    EXPECT_TRUE(std::equal(bobDerived.begin(), bobDerived.end(), bobExpected.begin()));
}

TEST(X25519, SharedSecretMatchesRfc7748AndIsSymmetric)
{
    const std::array<std::byte, 32> alicePrivate = fromHex32(kAlicePrivate);
    const std::array<std::byte, 32> bobPrivate   = fromHex32(kBobPrivate);
    const X25519KeyPair alice =
        x25519KeyPairFromScalar(std::span<const std::byte, 32>(alicePrivate));
    const X25519KeyPair bob = x25519KeyPairFromScalar(std::span<const std::byte, 32>(bobPrivate));
    const std::array<std::byte, 32> expected = fromHex32(kSharedSecret);

    const auto aliceView                     = x25519SharedSecret(alice.secretKey, bob.publicKey);
    ASSERT_TRUE(aliceView.has_value());
    EXPECT_EQ(*aliceView, expected);

    const auto bobView = x25519SharedSecret(bob.secretKey, alice.publicKey);
    ASSERT_TRUE(bobView.has_value());
    EXPECT_EQ(*bobView, expected); // both sides agree on the same secret
}

TEST(X25519, FreshKeyPairsAgreeOnAsharedSecret)
{
    const X25519KeyPair first  = generateX25519KeyPair();
    const X25519KeyPair second = generateX25519KeyPair();

    const auto firstView       = x25519SharedSecret(first.secretKey, second.publicKey);
    const auto secondView      = x25519SharedSecret(second.secretKey, first.publicKey);
    ASSERT_TRUE(firstView.has_value());
    ASSERT_TRUE(secondView.has_value());
    EXPECT_EQ(*firstView, *secondView);
}

TEST(X25519, RejectsLowOrderPeerPoint)
{
    const X25519KeyPair us = generateX25519KeyPair();
    std::array<std::byte, 32> allZero{}; // the identity is a low-order point
    const X25519PublicKey lowOrder{std::span<const std::byte, 32>(allZero)};

    EXPECT_FALSE(x25519SharedSecret(us.secretKey, lowOrder).has_value());
}
