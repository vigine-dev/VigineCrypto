#include <gtest/gtest.h>

#include "vigine/crypto/random.h"

#include <array>
#include <cstddef>
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

}

TEST(CryptoRandom, FillsBufferNonZero)
{
    std::array<std::byte, 32> buffer{};
    vigine::crypto::randomBytes(buffer);
    // A 32-byte all-zero draw is a 1-in-2^256 event.
    EXPECT_FALSE(allZero(buffer));
}

TEST(CryptoRandom, TwoCallsDiffer)
{
    std::array<std::byte, 32> first{};
    std::array<std::byte, 32> second{};
    vigine::crypto::randomBytes(first);
    vigine::crypto::randomBytes(second);
    EXPECT_NE(first, second);
}

TEST(CryptoRandom, EmptySpanIsNoop)
{
    std::span<std::byte> empty;
    vigine::crypto::randomBytes(empty);
    SUCCEED();
}

TEST(CryptoRandom, EnsureCsprngReadyDoesNotAbort)
{
    // A working OpenSSL DRBG must pass the startup self-check without aborting,
    // and repeated calls must be a no-op (the check runs once).
    vigine::crypto::ensureCsprngReady();
    vigine::crypto::ensureCsprngReady();
    SUCCEED();
}
