#include "vigine/crypto/compare.h"

#include <cstddef>
#include <gtest/gtest.h>
#include <vector>

namespace
{

std::vector<std::byte> sampleBytes(std::size_t size)
{
    std::vector<std::byte> out(size);
    for (std::size_t index = 0; index < size; ++index)
        out[index] = static_cast<std::byte>(index + 1);
    return out;
}

} // namespace

TEST(CompareTest, EqualSpansAreEqual)
{
    auto left  = sampleBytes(32);
    auto right = sampleBytes(32);
    EXPECT_TRUE(vigine::crypto::equalConstantTime(left, right));
}

TEST(CompareTest, DifferenceInLastByteIsUnequal)
{
    auto left  = sampleBytes(32);
    auto right = sampleBytes(32);
    right.back() ^= std::byte{1};
    EXPECT_FALSE(vigine::crypto::equalConstantTime(left, right));
}

TEST(CompareTest, DifferentSizesAreUnequal)
{
    auto left  = sampleBytes(32);
    auto right = sampleBytes(31);
    EXPECT_FALSE(vigine::crypto::equalConstantTime(left, right));
}

TEST(CompareTest, TwoEmptySpansAreEqual)
{
    EXPECT_TRUE(vigine::crypto::equalConstantTime({}, {}));
}
