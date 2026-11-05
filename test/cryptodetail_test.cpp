#include "../src/cryptodetail.h"

#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <stdexcept>
#include <vector>

using vigine::crypto::detail::SecretWipe;

namespace
{
using Secret = std::array<std::byte, 16>;

Secret filled()
{
    Secret secret{};
    secret.fill(std::byte{0xA5});
    return secret;
}

bool allZero(const std::byte *data, std::size_t size)
{
    for (std::size_t index = 0; index < size; ++index)
        if (data[index] != std::byte{0})
            return false;
    return true;
}

// Returns early on the failure path; the guard must wipe the buffer on that return too.
bool useThenReturnEarly(Secret &secret, bool fail)
{
    const SecretWipe wipe{secret};
    if (fail)
        return false;
    return true;
}

void throwsWhileHolding(Secret &secret)
{
    const SecretWipe wipe{secret};
    throw std::runtime_error{"derivation failed"};
}
} // namespace

TEST(SecretWipeTest, WipesArrayAtEndOfScope)
{
    Secret secret = filled();
    {
        const SecretWipe wipe{secret};
        EXPECT_FALSE(allZero(secret.data(), secret.size()));
    }
    EXPECT_TRUE(allZero(secret.data(), secret.size()));
}

TEST(SecretWipeTest, WipesOnEarlyReturn)
{
    Secret secret = filled();
    EXPECT_FALSE(useThenReturnEarly(secret, true));
    EXPECT_TRUE(allZero(secret.data(), secret.size()));
}

TEST(SecretWipeTest, WipesOnNormalReturn)
{
    Secret secret = filled();
    EXPECT_TRUE(useThenReturnEarly(secret, false));
    EXPECT_TRUE(allZero(secret.data(), secret.size()));
}

TEST(SecretWipeTest, WipesWhenExceptionUnwinds)
{
    Secret secret = filled();
    EXPECT_THROW(throwsWhileHolding(secret), std::runtime_error);
    EXPECT_TRUE(allZero(secret.data(), secret.size()));
}

TEST(SecretWipeTest, WipesWholeVectorIncludingGrownContents)
{
    std::vector<std::byte> transcript;
    transcript.reserve(64);
    {
        const SecretWipe wipe{transcript};
        transcript.assign(48, std::byte{0x3C});
        EXPECT_EQ(transcript.size(), 48U);
    }
    EXPECT_TRUE(allZero(transcript.data(), transcript.size()));
}
