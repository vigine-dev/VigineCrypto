#include <gtest/gtest.h>

#include "vigine/crypto/ed25519.h"

#include <cstddef>
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

}

TEST(Ed25519, SignVerifyRoundTrip)
{
    auto       pair      = vigine::crypto::generateKeyPair();
    const auto message   = bytesOf("the quick brown fox");
    const auto signature = vigine::crypto::sign(pair.secretKey, message);
    EXPECT_TRUE(vigine::crypto::verify(pair.publicKey, message, signature));
}

TEST(Ed25519, RejectsTamperedMessage)
{
    auto       pair      = vigine::crypto::generateKeyPair();
    auto       message   = bytesOf("authentic");
    const auto signature = vigine::crypto::sign(pair.secretKey, message);
    message[0]           = static_cast<std::byte>(0xFF);
    EXPECT_FALSE(vigine::crypto::verify(pair.publicKey, message, signature));
}

TEST(Ed25519, RejectsWrongKey)
{
    auto       signer    = vigine::crypto::generateKeyPair();
    auto       other     = vigine::crypto::generateKeyPair();
    const auto message   = bytesOf("hello");
    const auto signature = vigine::crypto::sign(signer.secretKey, message);
    EXPECT_FALSE(vigine::crypto::verify(other.publicKey, message, signature));
}

TEST(Ed25519, MovedSecretKeyStillSigns)
{
    auto       pair      = vigine::crypto::generateKeyPair();
    auto       moved     = std::move(pair.secretKey);
    const auto message   = bytesOf("after move");
    const auto signature = vigine::crypto::sign(moved, message);
    EXPECT_TRUE(vigine::crypto::verify(pair.publicKey, message, signature));
}
