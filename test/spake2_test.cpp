// SPAKE2 over P-256 against the first test vector of RFC 9382 (appendix B),
// then the behaviour a pairing leans on: the same code agrees, a different
// code does not, and bytes that are no point of the curve are refused.

#include "vigine/crypto/spake2.h"

#include <vigine/unittest/unittest.h>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
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

std::optional<std::unique_ptr<ISpake2Session>> vectorSide(Spake2Role role, std::string_view scalarHex)
{
    const std::vector<std::byte> scalar = fromHex(scalarHex);
    return beginSpake2WithScalar(
        role, fromHex(kW), bytesOf("server"), bytesOf("client"),
        std::span<const std::byte, kSpake2ScalarSize>{scalar.data(), kSpake2ScalarSize});
}

} // namespace

VIGINE_TEST(Spake2, BothSidesOfTheRfcVectorComeOutByteForByte)
{
    const auto sideA = vectorSide(Spake2Role::A, kX);
    const auto sideB = vectorSide(Spake2Role::B, kY);
    VIGINE_ASSERT_TRUE(sideA && sideB);
    VIGINE_EXPECT_EQ(asVector((*sideA)->share()), fromHex(kPA));
    VIGINE_EXPECT_EQ(asVector((*sideB)->share()), fromHex(kPB));

    const auto outcomeA = (*sideA)->finish((*sideB)->share());
    const auto outcomeB = (*sideB)->finish((*sideA)->share());
    VIGINE_ASSERT_TRUE(outcomeA && outcomeB);
    for (const Spake2Outcome *outcome : {&*outcomeA, &*outcomeB})
    {
        VIGINE_EXPECT_EQ(asVector(outcome->sharedKey()), fromHex(kKe));
        VIGINE_EXPECT_EQ(asVector(outcome->confirmationA()), fromHex(kConfirmationA));
        VIGINE_EXPECT_EQ(asVector(outcome->confirmationB()), fromHex(kConfirmationB));
    }
}

VIGINE_TEST(Spake2, TheSameCodeAgreesAndADifferentOneDoesNot)
{
    const auto identityA = bytesOf("map");
    const auto identityB = bytesOf("agent");
    const auto code      = spake2PasswordScalar("vigine.link.pairing", "734-218");
    const auto wrongCode = spake2PasswordScalar("vigine.link.pairing", "734-219");

    const auto sideA     = beginSpake2(Spake2Role::A, code, identityA, identityB);
    const auto sideB     = beginSpake2(Spake2Role::B, code, identityA, identityB);
    const auto impostor  = beginSpake2(Spake2Role::B, wrongCode, identityA, identityB);
    VIGINE_ASSERT_TRUE(sideA && sideB && impostor);
    VIGINE_EXPECT_NE(asVector((*sideA)->share()), asVector((*sideB)->share()));

    const auto outcomeA = (*sideA)->finish((*sideB)->share());
    const auto outcomeB = (*sideB)->finish((*sideA)->share());
    VIGINE_ASSERT_TRUE(outcomeA && outcomeB);
    VIGINE_EXPECT_EQ(asVector(outcomeA->sharedKey()), asVector(outcomeB->sharedKey()));
    VIGINE_EXPECT_TRUE(spake2ConfirmationsMatch(outcomeA->confirmationB(), outcomeB->confirmationB()));
    VIGINE_EXPECT_TRUE(spake2ConfirmationsMatch(outcomeA->confirmationA(), outcomeB->confirmationA()));

    const auto withImpostor = (*sideA)->finish((*impostor)->share());
    const auto impostorSide = (*impostor)->finish((*sideA)->share());
    VIGINE_ASSERT_TRUE(withImpostor && impostorSide);
    VIGINE_EXPECT_FALSE(spake2ConfirmationsMatch(withImpostor->confirmationB(), impostorSide->confirmationB()))
        << "a different code was confirmed";
    VIGINE_EXPECT_NE(asVector(withImpostor->sharedKey()), asVector(impostorSide->sharedKey()));
}

// The identities are part of what is proved: a party named differently by its peer is not
// confirmed.
VIGINE_TEST(Spake2, AnExchangeBetweenOtherIdentitiesIsNotConfirmed)
{
    const auto code  = spake2PasswordScalar("vigine.link.pairing", "734-218");
    const auto sideA = beginSpake2(Spake2Role::A, code, bytesOf("map"), bytesOf("agent"));
    const auto sideB = beginSpake2(Spake2Role::B, code, bytesOf("map"), bytesOf("someone else"));
    VIGINE_ASSERT_TRUE(sideA && sideB);
    const auto outcomeA = (*sideA)->finish((*sideB)->share());
    const auto outcomeB = (*sideB)->finish((*sideA)->share());
    VIGINE_ASSERT_TRUE(outcomeA && outcomeB);
    VIGINE_EXPECT_FALSE(spake2ConfirmationsMatch(outcomeA->confirmationB(), outcomeB->confirmationB()));
}

VIGINE_TEST(Spake2, BytesThatAreNoPointOfTheCurveAreRefused)
{
    const auto code  = spake2PasswordScalar("vigine.link.pairing", "734-218");
    const auto sideA = beginSpake2(Spake2Role::A, code, bytesOf("map"), bytesOf("agent"));
    VIGINE_ASSERT_TRUE(sideA);
    std::vector<std::byte> notAPoint(kSpake2ShareSize, std::byte{0x01});
    notAPoint[0] = std::byte{0x04};
    VIGINE_EXPECT_FALSE((*sideA)->finish(notAPoint).has_value());
    VIGINE_EXPECT_FALSE((*sideA)->finish(std::vector<std::byte>{}).has_value());
    VIGINE_EXPECT_FALSE((*sideA)->finish(std::vector<std::byte>{std::byte{0x00}}).has_value())
        << "the point at infinity was taken";
}

VIGINE_TEST(Spake2, AZeroPasswordScalarIsRefused)
{
    const std::vector<std::byte> zero(kSpake2ScalarSize, std::byte{0});
    VIGINE_EXPECT_FALSE(beginSpake2(Spake2Role::A, zero, bytesOf("map"), bytesOf("agent")).has_value());
}

VIGINE_TEST(Spake2, AReflectedShareIsRefused)
{
    const auto code  = spake2PasswordScalar("vigine.link.pairing", "734-218");
    const auto sideA = beginSpake2(Spake2Role::A, code, bytesOf("map"), bytesOf("agent"));
    VIGINE_ASSERT_TRUE(sideA);
    VIGINE_EXPECT_FALSE((*sideA)->finish((*sideA)->share()).has_value());
}

VIGINE_TEST(Spake2, ACodeMakesADifferentScalarForADifferentPurpose)
{
    VIGINE_EXPECT_NE(asVector(spake2PasswordScalar("vigine.link.pairing", "734-218")),
              asVector(spake2PasswordScalar("another.purpose", "734-218")));
    VIGINE_EXPECT_EQ(asVector(spake2PasswordScalar("vigine.link.pairing", "734-218")),
              asVector(spake2PasswordScalar("vigine.link.pairing", "734-218")));
}

namespace
{
bool allZero(const volatile unsigned char *bytes, std::size_t count)
{
    for (std::size_t index = 0; index < count; ++index)
        if (bytes[index] != 0)
            return false;
    return true;
}

std::array<std::byte, kSpake2KeySize> filledKey(unsigned char value)
{
    std::array<std::byte, kSpake2KeySize> key{};
    key.fill(std::byte{value});
    return key;
}
} // namespace

// The destructor runs on a placement buffer the test owns, so the bytes it leaves can be read
// afterwards; the confirmations are zero, so a non-zero byte could only be the key.
VIGINE_TEST(Spake2, TheSharedKeyIsWipedWhenTheOutcomeIsDestroyed)
{
    alignas(Spake2Outcome) unsigned char storage[sizeof(Spake2Outcome)];
    const std::array<std::byte, kSpake2ConfirmationSize> confirmation{};
    const auto key = filledKey(0xA5);
    auto *outcome  = new (storage) Spake2Outcome{key, confirmation, confirmation};
    VIGINE_ASSERT_EQ(outcome->sharedKey(), key);
    outcome->~Spake2Outcome();
    VIGINE_EXPECT_TRUE(allZero(storage, sizeof(storage)));
}

VIGINE_TEST(Spake2, AMovedFromOutcomeHoldsNoKeyAndTheTargetKeepsIt)
{
    const std::array<std::byte, kSpake2ConfirmationSize> confirmation{};
    const auto key = filledKey(0xA5);
    Spake2Outcome source{key, confirmation, confirmation};
    Spake2Outcome target{std::move(source)};
    VIGINE_EXPECT_EQ(target.sharedKey(), key);
    VIGINE_EXPECT_TRUE(allZero(reinterpret_cast<const unsigned char *>(source.sharedKey().data()),
                               source.sharedKey().size()));
}

VIGINE_TEST(Spake2, MoveAssignmentWipesTheOverwrittenKeyAndTheSource)
{
    const std::array<std::byte, kSpake2ConfirmationSize> confirmation{};
    const auto key = filledKey(0xA5);
    Spake2Outcome source{key, confirmation, confirmation};
    Spake2Outcome target{filledKey(0x5A), confirmation, confirmation};
    target = std::move(source);
    VIGINE_EXPECT_EQ(target.sharedKey(), key);
    VIGINE_EXPECT_TRUE(allZero(reinterpret_cast<const unsigned char *>(source.sharedKey().data()),
                               source.sharedKey().size()));
}
