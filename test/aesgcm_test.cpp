#include <gtest/gtest.h>

#include "vigine/crypto/aesgcm.h"

#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <string_view>
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

std::array<std::byte, vigine::crypto::kAesGcmNonceSize> sampleNonce()
{
    std::array<std::byte, vigine::crypto::kAesGcmNonceSize> nonce{};
    for (std::size_t index = 0; index < nonce.size(); ++index)
        nonce[index] = static_cast<std::byte>(index + 1);
    return nonce;
}

}

TEST(AesGcm, SealOpenRoundTrip)
{
    const auto key       = vigine::crypto::AesGcmKey::random();
    const auto nonce     = sampleNonce();
    const auto plaintext = bytesOf("attack at dawn");

    const auto sealed = vigine::crypto::seal(key, nonce, plaintext);
    const auto opened = vigine::crypto::open(key, nonce, sealed.ciphertext, sealed.tag);

    ASSERT_TRUE(opened.has_value());
    EXPECT_EQ(*opened, plaintext);
}

TEST(AesGcm, RoundTripWithAssociatedData)
{
    const auto key       = vigine::crypto::AesGcmKey::random();
    const auto nonce     = sampleNonce();
    const auto plaintext = bytesOf("body");
    const auto aad       = bytesOf("header-v1");

    const auto sealed = vigine::crypto::seal(key, nonce, plaintext, aad);
    EXPECT_TRUE(vigine::crypto::open(key, nonce, sealed.ciphertext, sealed.tag, aad).has_value());
    // Wrong associated data must fail authentication.
    EXPECT_FALSE(
        vigine::crypto::open(key, nonce, sealed.ciphertext, sealed.tag, bytesOf("header-v2")).has_value());
}

TEST(AesGcm, RejectsTamperedTag)
{
    const auto key       = vigine::crypto::AesGcmKey::random();
    const auto nonce     = sampleNonce();
    const auto plaintext = bytesOf("secret");

    auto sealed = vigine::crypto::seal(key, nonce, plaintext);
    sealed.tag[0] = static_cast<std::byte>(static_cast<unsigned>(sealed.tag[0]) ^ 0xFFu);
    EXPECT_FALSE(vigine::crypto::open(key, nonce, sealed.ciphertext, sealed.tag).has_value());
}

TEST(AesGcm, RejectsWrongKey)
{
    const auto key       = vigine::crypto::AesGcmKey::random();
    const auto other     = vigine::crypto::AesGcmKey::random();
    const auto nonce     = sampleNonce();
    const auto plaintext = bytesOf("secret");

    const auto sealed = vigine::crypto::seal(key, nonce, plaintext);
    EXPECT_FALSE(vigine::crypto::open(other, nonce, sealed.ciphertext, sealed.tag).has_value());
}

TEST(AesGcm, EmptyPlaintextRoundTrips)
{
    const auto key   = vigine::crypto::AesGcmKey::random();
    const auto nonce = sampleNonce();

    const auto sealed = vigine::crypto::seal(key, nonce, {});
    const auto opened = vigine::crypto::open(key, nonce, sealed.ciphertext, sealed.tag);
    ASSERT_TRUE(opened.has_value());
    EXPECT_TRUE(opened->empty());
}

TEST(AesGcm, AssociatedDataOnlyEmptyPlaintext)
{
    const auto key   = vigine::crypto::AesGcmKey::random();
    const auto nonce = sampleNonce();
    const auto aad   = bytesOf("header-only");

    // Empty plaintext + non-empty AAD previously formed an out-of-bounds
    // pointer (ciphertext.data() + aadLen); it must seal/open cleanly now.
    const auto sealed = vigine::crypto::seal(key, nonce, {}, aad);
    EXPECT_TRUE(sealed.ciphertext.empty());
    const auto opened = vigine::crypto::open(key, nonce, sealed.ciphertext, sealed.tag, aad);
    ASSERT_TRUE(opened.has_value());
    EXPECT_TRUE(opened->empty());
    EXPECT_FALSE(
        vigine::crypto::open(key, nonce, sealed.ciphertext, sealed.tag, bytesOf("other")).has_value());
}
