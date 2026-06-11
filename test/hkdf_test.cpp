#include "vigine/crypto/hkdf.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

using namespace vigine::crypto;

namespace
{
std::vector<std::byte> fromHex(std::string_view hex)
{
    auto nibble = [](char character) -> int
    {
        if (character >= '0' && character <= '9')
            return character - '0';
        return (character - 'a') + 10;
    };
    std::vector<std::byte> out;
    out.reserve(hex.size() / 2);
    for (std::size_t index = 0; index + 1 < hex.size(); index += 2)
        out.push_back(static_cast<std::byte>((nibble(hex[index]) << 4) | nibble(hex[index + 1])));
    return out;
}
} // namespace

// RFC 5869 Appendix A.1 -- HKDF-SHA256 basic test case.
TEST(Hkdf, MatchesRfc5869TestCase1)
{
    const std::vector<std::byte> ikm  = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const std::vector<std::byte> salt = fromHex("000102030405060708090a0b0c");
    const std::vector<std::byte> info = fromHex("f0f1f2f3f4f5f6f7f8f9");
    const std::vector<std::byte> expected =
        fromHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    const std::vector<std::byte> okm = hkdfSha256(ikm, salt, info, 42);
    EXPECT_EQ(okm, expected);
}

TEST(Hkdf, ZeroLengthReturnsEmpty)
{
    const std::vector<std::byte> ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    EXPECT_TRUE(hkdfSha256(ikm, {}, {}, 0).empty());
}

TEST(Hkdf, DifferentInfoYieldsDifferentKey)
{
    const std::vector<std::byte> ikm   = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const std::vector<std::byte> salt  = fromHex("000102030405060708090a0b0c");
    const std::vector<std::byte> infoA = fromHex("f0f1f2f3f4f5f6f7f8f9");
    const std::vector<std::byte> infoB = fromHex("0102030405060708090a");

    const std::vector<std::byte> keyA = hkdfSha256(ikm, salt, infoA, 32);
    const std::vector<std::byte> keyB = hkdfSha256(ikm, salt, infoB, 32);
    ASSERT_EQ(keyA.size(), 32u);
    ASSERT_EQ(keyB.size(), 32u);
    EXPECT_NE(keyA, keyB);
}

TEST(Hkdf, RejectsOutputBeyondHkdfCeiling)
{
    const std::vector<std::byte> ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    // 255*32 = 8160 is the max for SHA-256; one more must fail.
    EXPECT_TRUE(hkdfSha256(ikm, {}, {}, 8161).empty());
}

TEST(Hkdf, RejectsEmptySecret)
{
    const std::vector<std::byte> salt = fromHex("000102030405060708090a0b0c");
    EXPECT_TRUE(hkdfSha256({}, salt, {}, 32).empty());
}
