#include "vigine/crypto/hash.h"

#include <array>
#include <cstddef>
#include <gtest/gtest.h>
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

} // namespace

TEST(Blake3, EmptyInputMatchesKnownVector)
{
    // Official BLAKE3 hash of the empty input.
    const std::array<std::byte, 32> expected = {
        std::byte{0xaf}, std::byte{0x13}, std::byte{0x49}, std::byte{0xb9}, std::byte{0xf5},
        std::byte{0xf9}, std::byte{0xa1}, std::byte{0xa6}, std::byte{0xa0}, std::byte{0x40},
        std::byte{0x4d}, std::byte{0xea}, std::byte{0x36}, std::byte{0xdc}, std::byte{0xc9},
        std::byte{0x49}, std::byte{0x9b}, std::byte{0xcb}, std::byte{0x25}, std::byte{0xc9},
        std::byte{0xad}, std::byte{0xc1}, std::byte{0x12}, std::byte{0xb7}, std::byte{0xcc},
        std::byte{0x9a}, std::byte{0x93}, std::byte{0xca}, std::byte{0xe4}, std::byte{0x1f},
        std::byte{0x32}, std::byte{0x62},
    };
    EXPECT_EQ(vigine::crypto::blake3({}), expected);
}

TEST(Blake3, OneShotMatchesStreaming)
{
    const auto part1             = bytesOf("the quick brown ");
    const auto part2             = bytesOf("fox jumps over the lazy dog");
    std::vector<std::byte> whole = part1;
    whole.insert(whole.end(), part2.begin(), part2.end());

    vigine::crypto::Blake3Hasher hasher;
    hasher.update(part1);
    hasher.update(part2);

    EXPECT_EQ(hasher.finalize(), vigine::crypto::blake3(whole));
}
