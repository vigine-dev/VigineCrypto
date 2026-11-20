#include "vigine/crypto/random.h"

#include <array>
#include <cstddef>
#include <vigine/unittest/unittest.h>
#include <span>

namespace
{

bool allZero(std::span<const std::byte> bytes)
{
    for (std::byte value : bytes)
        if (value != std::byte{0})
            return false;
    return true;
}

} // namespace

VIGINE_TEST(CryptoRandom, FillsBufferNonZero)
{
    std::array<std::byte, 32> buffer{};
    vigine::crypto::randomBytes(buffer);
    // A 32-byte all-zero draw is a 1-in-2^256 event.
    VIGINE_EXPECT_FALSE(allZero(buffer));
}

VIGINE_TEST(CryptoRandom, TwoCallsDiffer)
{
    std::array<std::byte, 32> first{};
    std::array<std::byte, 32> second{};
    vigine::crypto::randomBytes(first);
    vigine::crypto::randomBytes(second);
    VIGINE_EXPECT_NE(first, second);
}

VIGINE_TEST(CryptoRandom, EmptySpanIsNoop)
{
    std::span<std::byte> empty;
    vigine::crypto::randomBytes(empty);
    SUCCEED();
}

VIGINE_TEST(CryptoRandom, EnsureCsprngReadyDoesNotAbort)
{
    // A working OpenSSL DRBG must pass the startup self-check without aborting,
    // and repeated calls must be a no-op (the check runs once).
    vigine::crypto::ensureCsprngReady();
    vigine::crypto::ensureCsprngReady();
    SUCCEED();
}
