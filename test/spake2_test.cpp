// SPAKE2 over P-256 against the first test vector of RFC 9382 (appendix B),
// then the behaviour a pairing leans on: the same code agrees, a different
// code does not, and bytes that are no point of the curve are refused.

#include "vigine/crypto/spake2.h"

#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using namespace vigine::crypto;

std::vector<std::byte> fromHex(std::string_view hex)
{
    std::vector<std::byte> bytes;
    for (std::size_t index = 0; index + 1 < hex.size(); index += 2)
        bytes.push_back(
            static_cast<std::byte>(std::stoi(std::string{hex.substr(index, 2)}, nullptr, 16)));
    return bytes;
}

std::vector<std::byte> bytesOf(std::string_view text)
{
    std::vector<std::byte> bytes;
    for (const char character : text)
        bytes.push_back(static_cast<std::byte>(character));
    return bytes;
}

template <std::size_t Size>
std::vector<std::byte> asVector(std::span<const std::byte, Size> bytes)
{
    return std::vector<std::byte>(bytes.begin(), bytes.end());
}

template <std::size_t Size>
std::vector<std::byte> asVector(const std::array<std::byte, Size> &bytes)
{
    return std::vector<std::byte>(bytes.begin(), bytes.end());
}

constexpr std::string_view kW = "2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f";
constexpr std::string_view kX = "43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729";
constexpr std::string_view kY = "dcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be";
constexpr std::string_view kPA =
    "04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470"
    "f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c";
constexpr std::string_view kPB =
    "0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676"
    "d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7";
constexpr std::string_view kKe = "0e0672dc86f8e45565d338b0540abe69";
constexpr std::string_view kConfirmationA =
    "58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0";
constexpr std::string_view kConfirmationB =
    "d3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b";

std::optional<Spake2> vectorSide(Spake2Role role, std::string_view scalarHex)
{
    const std::vector<std::byte> scalar = fromHex(scalarHex);
    return Spake2::beginWithScalar(
        role, fromHex(kW), bytesOf("server"), bytesOf("client"),
        std::span<const std::byte, kSpake2ScalarSize>{scalar.data(), kSpake2ScalarSize});
}

} // namespace

TEST(Spake2, BothSidesOfTheRfcVectorComeOutByteForByte)
{
    const auto sideA = vectorSide(Spake2Role::A, kX);
    const auto sideB = vectorSide(Spake2Role::B, kY);
    ASSERT_TRUE(sideA && sideB);
    EXPECT_EQ(asVector(sideA->share()), fromHex(kPA));
    EXPECT_EQ(asVector(sideB->share()), fromHex(kPB));

    const auto outcomeA = sideA->finish(sideB->share());
    const auto outcomeB = sideB->finish(sideA->share());
    ASSERT_TRUE(outcomeA && outcomeB);
    for (const Spake2Outcome *outcome : {&*outcomeA, &*outcomeB})
    {
        EXPECT_EQ(asVector(outcome->sharedKey), fromHex(kKe));
        EXPECT_EQ(asVector(outcome->confirmationA), fromHex(kConfirmationA));
        EXPECT_EQ(asVector(outcome->confirmationB), fromHex(kConfirmationB));
    }
}

TEST(Spake2, TheSameCodeAgreesAndADifferentOneDoesNot)
{
    const auto identityA = bytesOf("map");
    const auto identityB = bytesOf("agent");
    const auto code      = spake2PasswordScalar("vigine.link.pairing", "734-218");
    const auto wrongCode = spake2PasswordScalar("vigine.link.pairing", "734-219");

    const auto sideA     = Spake2::begin(Spake2Role::A, code, identityA, identityB);
    const auto sideB     = Spake2::begin(Spake2Role::B, code, identityA, identityB);
    const auto impostor  = Spake2::begin(Spake2Role::B, wrongCode, identityA, identityB);
    ASSERT_TRUE(sideA && sideB && impostor);
    EXPECT_NE(asVector(sideA->share()), asVector(sideB->share()));

    const auto outcomeA = sideA->finish(sideB->share());
    const auto outcomeB = sideB->finish(sideA->share());
    ASSERT_TRUE(outcomeA && outcomeB);
    EXPECT_EQ(asVector(outcomeA->sharedKey), asVector(outcomeB->sharedKey));
    EXPECT_TRUE(spake2ConfirmationsMatch(outcomeA->confirmationB, outcomeB->confirmationB));
    EXPECT_TRUE(spake2ConfirmationsMatch(outcomeA->confirmationA, outcomeB->confirmationA));

    const auto withImpostor = sideA->finish(impostor->share());
    const auto impostorSide = impostor->finish(sideA->share());
    ASSERT_TRUE(withImpostor && impostorSide);
    EXPECT_FALSE(spake2ConfirmationsMatch(withImpostor->confirmationB, impostorSide->confirmationB))
        << "a different code was confirmed";
    EXPECT_NE(asVector(withImpostor->sharedKey), asVector(impostorSide->sharedKey));
}

// The identities are part of what is proved: a party named differently by its peer is not
// confirmed.
TEST(Spake2, AnExchangeBetweenOtherIdentitiesIsNotConfirmed)
{
    const auto code  = spake2PasswordScalar("vigine.link.pairing", "734-218");
    const auto sideA = Spake2::begin(Spake2Role::A, code, bytesOf("map"), bytesOf("agent"));
    const auto sideB = Spake2::begin(Spake2Role::B, code, bytesOf("map"), bytesOf("someone else"));
    ASSERT_TRUE(sideA && sideB);
    const auto outcomeA = sideA->finish(sideB->share());
    const auto outcomeB = sideB->finish(sideA->share());
    ASSERT_TRUE(outcomeA && outcomeB);
    EXPECT_FALSE(spake2ConfirmationsMatch(outcomeA->confirmationB, outcomeB->confirmationB));
}

TEST(Spake2, BytesThatAreNoPointOfTheCurveAreRefused)
{
    const auto code  = spake2PasswordScalar("vigine.link.pairing", "734-218");
    const auto sideA = Spake2::begin(Spake2Role::A, code, bytesOf("map"), bytesOf("agent"));
    ASSERT_TRUE(sideA);
    std::vector<std::byte> notAPoint(kSpake2ShareSize, std::byte{0x01});
    notAPoint[0] = std::byte{0x04};
    EXPECT_FALSE(sideA->finish(notAPoint).has_value());
    EXPECT_FALSE(sideA->finish(std::vector<std::byte>{}).has_value());
    EXPECT_FALSE(sideA->finish(std::vector<std::byte>{std::byte{0x00}}).has_value())
        << "the point at infinity was taken";
}

TEST(Spake2, ACodeMakesADifferentScalarForADifferentPurpose)
{
    EXPECT_NE(asVector(spake2PasswordScalar("vigine.link.pairing", "734-218")),
              asVector(spake2PasswordScalar("another.purpose", "734-218")));
    EXPECT_EQ(asVector(spake2PasswordScalar("vigine.link.pairing", "734-218")),
              asVector(spake2PasswordScalar("vigine.link.pairing", "734-218")));
}
