#include "vigine/crypto/ed25519.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

std::vector<std::byte> bytesOf(std::string_view text)
{
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (char character : text)
        out.push_back(static_cast<std::byte>(character));
    return out;
}

template <std::size_t N>
std::array<std::byte, N> fromHex(std::string_view hex)
{
    auto nibble = [](char character) -> int {
        if (character >= '0' && character <= '9')
            return character - '0';
        if (character >= 'a' && character <= 'f')
            return character - 'a' + 10;
        return 0;
    };
    std::array<std::byte, N> out{};
    for (std::size_t index = 0; index < N; ++index)
        out[index] =
            static_cast<std::byte>((nibble(hex[index * 2]) << 4) | nibble(hex[index * 2 + 1]));
    return out;
}

} // namespace

TEST(Ed25519, SignVerifyRoundTrip)
{
    auto pair            = vigine::crypto::generateKeyPair();
    const auto message   = bytesOf("the quick brown fox");
    const auto signature = vigine::crypto::sign(pair.secretKey, message);
    EXPECT_TRUE(vigine::crypto::verify(pair.publicKey, message, signature));
}

TEST(Ed25519, RejectsTamperedMessage)
{
    auto pair            = vigine::crypto::generateKeyPair();
    auto message         = bytesOf("authentic");
    const auto signature = vigine::crypto::sign(pair.secretKey, message);
    message[0]           = static_cast<std::byte>(0xFF);
    EXPECT_FALSE(vigine::crypto::verify(pair.publicKey, message, signature));
}

TEST(Ed25519, RejectsWrongKey)
{
    auto signer          = vigine::crypto::generateKeyPair();
    auto other           = vigine::crypto::generateKeyPair();
    const auto message   = bytesOf("hello");
    const auto signature = vigine::crypto::sign(signer.secretKey, message);
    EXPECT_FALSE(vigine::crypto::verify(other.publicKey, message, signature));
}

TEST(Ed25519, MovedSecretKeyStillSigns)
{
    auto pair            = vigine::crypto::generateKeyPair();
    auto moved           = std::move(pair.secretKey);
    const auto message   = bytesOf("after move");
    const auto signature = vigine::crypto::sign(moved, message);
    EXPECT_TRUE(vigine::crypto::verify(pair.publicKey, message, signature));
}

TEST(Ed25519, Rfc8032TestVector1KnownAnswer)
{
    // RFC 8032 Section 7.1, Test 1 (empty message). Pins the wiring against a
    // published seed -> public key -> signature, so a curve/seed/export mix-up
    // cannot pass merely by sign and verify agreeing with each other.
    const auto seed = fromHex<vigine::crypto::kEd25519SeedSize>(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const auto expectedPublic = fromHex<vigine::crypto::kEd25519PublicKeySize>(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const auto expectedSignature = fromHex<vigine::crypto::kEd25519SignatureSize>(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
        "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    auto pair = vigine::crypto::keyPairFromSeed(
        std::span<const std::byte, vigine::crypto::kEd25519SeedSize>{seed});
    const auto publicBytes = pair.publicKey.bytes();
    EXPECT_TRUE(std::equal(publicBytes.begin(), publicBytes.end(), expectedPublic.begin()));

    const auto signature = vigine::crypto::sign(pair.secretKey, std::span<const std::byte>{});
    EXPECT_TRUE(std::equal(signature.begin(), signature.end(), expectedSignature.begin()));
    EXPECT_TRUE(vigine::crypto::verify(pair.publicKey, std::span<const std::byte>{}, signature));
}

TEST(Ed25519, RejectsTamperedSignatureBytes)
{
    auto pair          = vigine::crypto::generateKeyPair();
    const auto message = bytesOf("pin me");
    auto signature     = vigine::crypto::sign(pair.secretKey, message);
    signature[0]       = static_cast<std::byte>(static_cast<unsigned>(signature[0]) ^ 0xFFu);
    EXPECT_FALSE(vigine::crypto::verify(pair.publicKey, message, signature));
}
