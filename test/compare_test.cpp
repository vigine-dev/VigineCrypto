#include "vigine/crypto/compare.h"

#include <cstddef>
#include <vigine/unittest/unittest.h>
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

VIGINE_TEST(CompareTest, EqualSpansAreEqual)
{
    auto left  = sampleBytes(32);
    auto right = sampleBytes(32);
    VIGINE_EXPECT_TRUE(vigine::crypto::equalConstantTime(left, right));
}

VIGINE_TEST(CompareTest, DifferenceInLastByteIsUnequal)
{
    auto left  = sampleBytes(32);
    auto right = sampleBytes(32);
    right.back() ^= std::byte{1};
    VIGINE_EXPECT_FALSE(vigine::crypto::equalConstantTime(left, right));
}

VIGINE_TEST(CompareTest, DifferentSizesAreUnequal)
{
    auto left  = sampleBytes(32);
    auto right = sampleBytes(31);
    VIGINE_EXPECT_FALSE(vigine::crypto::equalConstantTime(left, right));
}

VIGINE_TEST(CompareTest, TwoEmptySpansAreEqual)
{
    VIGINE_EXPECT_TRUE(vigine::crypto::equalConstantTime({}, {}));
}
