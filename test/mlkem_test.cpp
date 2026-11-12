#include "vigine/crypto/mlkem.h"

#include <array>
#include <cstddef>
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
