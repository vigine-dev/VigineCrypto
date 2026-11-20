#include "vigine/crypto/mlkem.h"

#include <array>
#include <cstddef>
#include <new>
#include <utility>
#include <vigine/unittest/unittest.h>
#include <span>

using namespace vigine::crypto;

VIGINE_TEST(MlKem, TheSecretOneEndEncapsulatesIsTheSecretTheOtherDecapsulates)
{
    const MlKemKeyPair receiver                  = generateMlKemKeyPair();
    const std::optional<MlKemEncapsulation> sent = mlKemEncapsulate(receiver.publicKey());
    VIGINE_ASSERT_TRUE(sent.has_value());
    const auto opened = mlKemDecapsulate(
        receiver.secretKey(), std::span<const std::byte, kMlKem768CiphertextSize>{sent->ciphertext()});
    VIGINE_ASSERT_TRUE(opened.has_value());
    VIGINE_EXPECT_EQ(*opened, sent->sharedSecret());
}

VIGINE_TEST(MlKem, EachEncapsulationIsFreshForTheSameKey)
{
    const MlKemKeyPair receiver = generateMlKemKeyPair();
    const auto first            = mlKemEncapsulate(receiver.publicKey());
    const auto second           = mlKemEncapsulate(receiver.publicKey());
    VIGINE_ASSERT_TRUE(first.has_value() && second.has_value());
    VIGINE_EXPECT_NE(first->ciphertext(), second->ciphertext());
    VIGINE_EXPECT_NE(first->sharedSecret(), second->sharedSecret());
}

// Another key, or a tampered ciphertext, opens to an unrelated secret: implicit rejection.
VIGINE_TEST(MlKem, AnotherKeyOrATamperedCiphertextOpensToAnotherSecret)
{
    const MlKemKeyPair receiver = generateMlKemKeyPair();
    const MlKemKeyPair stranger = generateMlKemKeyPair();
    const auto sent             = mlKemEncapsulate(receiver.publicKey());
    VIGINE_ASSERT_TRUE(sent.has_value());
    const auto ciphertext = std::span<const std::byte, kMlKem768CiphertextSize>{sent->ciphertext()};

    const auto byStranger = mlKemDecapsulate(stranger.secretKey(), ciphertext);
    VIGINE_ASSERT_TRUE(byStranger.has_value());
    VIGINE_EXPECT_NE(*byStranger, sent->sharedSecret());

    std::array<std::byte, kMlKem768CiphertextSize> tampered  = sent->ciphertext();
    tampered[17]                                            ^= std::byte{0x01};
    const auto fromTampered                                  = mlKemDecapsulate(
        receiver.secretKey(), std::span<const std::byte, kMlKem768CiphertextSize>{tampered});
    VIGINE_ASSERT_TRUE(fromTampered.has_value());
    VIGINE_EXPECT_NE(*fromTampered, sent->sharedSecret());
}

VIGINE_TEST(MlKem, AKeyThatIsNotAnEncapsulationKeyIsRefused)
{
    std::array<std::byte, kMlKem768PublicKeySize> notAKey{};
    notAKey.fill(std::byte{0xFF});
    VIGINE_EXPECT_FALSE(mlKemEncapsulate(
                     MlKemPublicKey{std::span<const std::byte, kMlKem768PublicKeySize>{notAKey}})
                     .has_value());
}

namespace
{
constexpr std::array<std::byte, kMlKemSharedSecretSize> filledSecret()
{
    std::array<std::byte, kMlKemSharedSecretSize> secret{};
    for (std::byte &value : secret)
        value = std::byte{0xA5};
    return secret;
}

bool allZero(const volatile unsigned char *bytes, std::size_t count)
{
    for (std::size_t index = 0; index < count; ++index)
        if (bytes[index] != 0)
            return false;
    return true;
}
} // namespace

// The destructor runs on a placement buffer the test owns, so the bytes it leaves can be read
// afterwards without touching a destroyed object's members.
VIGINE_TEST(MlKem, TheSharedSecretIsWipedWhenTheEncapsulationIsDestroyed)
{
    alignas(MlKemEncapsulation) unsigned char storage[sizeof(MlKemEncapsulation)];
    const std::array<std::byte, kMlKem768CiphertextSize> ciphertext{};
    const auto secret                  = filledSecret();
    MlKemEncapsulation *encapsulation = new (storage) MlKemEncapsulation{ciphertext, secret};
    VIGINE_ASSERT_EQ(encapsulation->sharedSecret(), secret);
    encapsulation->~MlKemEncapsulation();
    // The shared secret is the only member written with a non-zero pattern; the ciphertext is zero.
    VIGINE_EXPECT_TRUE(allZero(storage, sizeof(storage)));
}

VIGINE_TEST(MlKem, AMovedFromEncapsulationHoldsNoSecretAndTheTargetKeepsIt)
{
    const std::array<std::byte, kMlKem768CiphertextSize> ciphertext{};
    const auto secret = filledSecret();
    MlKemEncapsulation source{ciphertext, secret};
    MlKemEncapsulation target{std::move(source)};
    VIGINE_EXPECT_EQ(target.sharedSecret(), secret);
    VIGINE_EXPECT_TRUE(allZero(reinterpret_cast<const unsigned char *>(source.sharedSecret().data()),
                               source.sharedSecret().size()));
}

VIGINE_TEST(MlKem, MoveAssignmentWipesTheOverwrittenSecretAndTheSource)
{
    const std::array<std::byte, kMlKem768CiphertextSize> ciphertext{};
    const auto secret = filledSecret();
    std::array<std::byte, kMlKemSharedSecretSize> other{};
    other.fill(std::byte{0x5A});
    MlKemEncapsulation source{ciphertext, secret};
    MlKemEncapsulation target{ciphertext, other};
    target = std::move(source);
    VIGINE_EXPECT_EQ(target.sharedSecret(), secret);
    VIGINE_EXPECT_TRUE(allZero(reinterpret_cast<const unsigned char *>(source.sharedSecret().data()),
                               source.sharedSecret().size()));
}
