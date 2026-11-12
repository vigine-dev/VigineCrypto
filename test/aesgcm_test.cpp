#include "vigine/crypto/aesgcm.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vigine/unittest/unittest.h>
#include <limits>
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

} // namespace

VIGINE_TEST(AesGcm, SealOpenRoundTrip)
{
    const auto key       = vigine::crypto::AesGcmKey::random();
    const auto nonce     = sampleNonce();
    const auto plaintext = bytesOf("attack at dawn");

    const auto sealed    = vigine::crypto::seal(key, nonce, plaintext);
    const auto opened    = vigine::crypto::open(key, nonce, sealed.ciphertext(), sealed.tag());

    VIGINE_ASSERT_TRUE(opened.has_value());
    VIGINE_EXPECT_EQ(*opened, plaintext);
}

VIGINE_TEST(AesGcm, RoundTripWithAssociatedData)
{
    const auto key       = vigine::crypto::AesGcmKey::random();
    const auto nonce     = sampleNonce();
    const auto plaintext = bytesOf("body");
    const auto aad       = bytesOf("header-v1");

    const auto sealed    = vigine::crypto::seal(key, nonce, plaintext, aad);
    VIGINE_EXPECT_TRUE(vigine::crypto::open(key, nonce, sealed.ciphertext(), sealed.tag(), aad).has_value());
    // Wrong associated data must fail authentication.
    VIGINE_EXPECT_FALSE(
        vigine::crypto::open(key, nonce, sealed.ciphertext(), sealed.tag(), bytesOf("header-v2"))
            .has_value());
}

VIGINE_TEST(AesGcm, RejectsTamperedTag)
{
    const auto key       = vigine::crypto::AesGcmKey::random();
    const auto nonce     = sampleNonce();
    const auto plaintext = bytesOf("secret");

    const auto sealed    = vigine::crypto::seal(key, nonce, plaintext);
    auto tag             = sealed.tag();
    tag[0]               = static_cast<std::byte>(static_cast<unsigned>(tag[0]) ^ 0xFFu);
    VIGINE_EXPECT_FALSE(vigine::crypto::open(key, nonce, sealed.ciphertext(), tag).has_value());
}

VIGINE_TEST(AesGcm, RejectsWrongKey)
{
    const auto key       = vigine::crypto::AesGcmKey::random();
    const auto other     = vigine::crypto::AesGcmKey::random();
    const auto nonce     = sampleNonce();
    const auto plaintext = bytesOf("secret");

    const auto sealed    = vigine::crypto::seal(key, nonce, plaintext);
    VIGINE_EXPECT_FALSE(vigine::crypto::open(other, nonce, sealed.ciphertext(), sealed.tag()).has_value());
}

VIGINE_TEST(AesGcm, EmptyPlaintextRoundTrips)
{
    const auto key    = vigine::crypto::AesGcmKey::random();
    const auto nonce  = sampleNonce();

    const auto sealed = vigine::crypto::seal(key, nonce, {});
    const auto opened = vigine::crypto::open(key, nonce, sealed.ciphertext(), sealed.tag());
    VIGINE_ASSERT_TRUE(opened.has_value());
    VIGINE_EXPECT_TRUE(opened->empty());
}

VIGINE_TEST(AesGcm, AssociatedDataOnlyEmptyPlaintext)
{
    const auto key   = vigine::crypto::AesGcmKey::random();
    const auto nonce = sampleNonce();
    const auto aad   = bytesOf("header-only");

    // Empty plaintext + non-empty AAD previously formed an out-of-bounds
    // pointer (ciphertext.data() + aadLen); it must seal/open cleanly now.
    const auto sealed = vigine::crypto::seal(key, nonce, {}, aad);
    VIGINE_EXPECT_TRUE(sealed.ciphertext().empty());
    const auto opened = vigine::crypto::open(key, nonce, sealed.ciphertext(), sealed.tag(), aad);
    VIGINE_ASSERT_TRUE(opened.has_value());
    VIGINE_EXPECT_TRUE(opened->empty());
    VIGINE_EXPECT_FALSE(vigine::crypto::open(key, nonce, sealed.ciphertext(), sealed.tag(), bytesOf("other"))
                     .has_value());
}

namespace
{

std::array<std::byte, vigine::crypto::kAesGcmKeySize> sampleKey()
{
    std::array<std::byte, vigine::crypto::kAesGcmKeySize> key{};
    for (std::size_t index = 0; index < key.size(); ++index)
        key[index] = static_cast<std::byte>(0xA0 + index);
    return key;
}

std::array<std::byte, vigine::crypto::kAesGcmNonceSize> nonceNumber(std::uint64_t number)
{
    std::array<std::byte, vigine::crypto::kAesGcmNonceSize> nonce{};
    for (std::size_t index = 0; index < 8; ++index)
        nonce[4 + index] = static_cast<std::byte>(number >> (8 * index));
    return nonce;
}

} // namespace

// The kept cipher seals what the one-shot seal does, message after message, each with its nonce.
VIGINE_TEST(AesGcm, AKeptCipherSealsWhatTheOneShotSealDoesForEveryNonce)
{
    const auto keyBytes = sampleKey();
    const vigine::crypto::AesGcmKey key{keyBytes};
    const auto cipher = vigine::crypto::createAesGcmCipher(keyBytes);
    const auto plaintext = bytesOf("one frame of a tunnel, sealed in place");
    const auto aad       = bytesOf("length");
    for (std::uint64_t number = 0; number < 1000; ++number)
    {
        const auto nonce = nonceNumber(number);
        std::vector<std::byte> out(plaintext.size());
        std::array<std::byte, vigine::crypto::kAesGcmTagSize> tag{};
        cipher->seal(nonce, plaintext, aad, out, tag);
        const auto oneShot = vigine::crypto::seal(key, nonce, plaintext, aad);
        VIGINE_ASSERT_EQ(out, oneShot.ciphertext()) << "message " << number;
        VIGINE_ASSERT_EQ(tag, oneShot.tag()) << "message " << number;
    }
}

// Sealed and opened in the same buffer; a tag that does not hold leaves nothing readable.
VIGINE_TEST(AesGcm, AKeptCipherOpensInPlaceAndRefusesATagThatDoesNotHold)
{
    const auto sender = vigine::crypto::createAesGcmCipher(sampleKey());
    const auto receiver = vigine::crypto::createAesGcmCipher(sampleKey());
    const auto plaintext          = bytesOf("sealed and opened in the same bytes");
    const auto nonce              = nonceNumber(7);
    std::vector<std::byte> buffer = plaintext;
    std::array<std::byte, vigine::crypto::kAesGcmTagSize> tag{};
    sender->seal(nonce, buffer, {}, buffer, tag);
    VIGINE_EXPECT_NE(buffer, plaintext);
    std::vector<std::byte> tampered = buffer;

    VIGINE_ASSERT_TRUE(receiver->open(nonce, buffer, tag, {}, buffer));
    VIGINE_EXPECT_EQ(buffer, plaintext);

    tampered[0] ^= std::byte{1};
    VIGINE_EXPECT_FALSE(receiver->open(nonce, tampered, tag, {}, tampered));
    VIGINE_EXPECT_EQ(tampered, std::vector<std::byte>(tampered.size()))
        << "what did not hold is wiped, not handed out";
    std::vector<std::byte> sealed(plaintext.size());
    sender->seal(nonce, plaintext, {}, sealed, tag);
    std::vector<std::byte> opened(sealed.size());
    VIGINE_EXPECT_FALSE(receiver->open(nonceNumber(8), sealed, tag, {}, opened))
        << "another nonce does not open it";
}

// The size check runs before any byte is read or allocated, so the spans below only
// claim a length above INT_MAX over a small buffer; nothing past it is dereferenced.
VIGINE_TEST(AesGcm, RefusesSizesAboveIntMaxBeforeOpenSsl)
{
    const auto key       = vigine::crypto::AesGcmKey::random();
    const auto nonce     = sampleNonce();
    const std::array<std::byte, vigine::crypto::kAesGcmTagSize> tag{};
    const std::vector<std::byte> small(16);
    const auto tooLong = static_cast<std::size_t>(std::numeric_limits<int>::max()) + 1;

    const std::span<const std::byte> forgedCiphertext(small.data(), tooLong);
    VIGINE_EXPECT_FALSE(vigine::crypto::open(key, nonce, forgedCiphertext, tag).has_value());

    const std::span<const std::byte> forgedAad(small.data(), tooLong);
    VIGINE_EXPECT_FALSE(vigine::crypto::open(key, nonce, {}, tag, forgedAad).has_value());

    const auto cipher = vigine::crypto::createAesGcmCipher(sampleKey());
    std::vector<std::byte> out(16);
    VIGINE_EXPECT_FALSE(cipher->open(nonceNumber(1), forgedCiphertext, tag, {}, out));
}
