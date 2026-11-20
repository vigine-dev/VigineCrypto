#include "../src/cryptodetail.h"

#include <array>
#include <cstddef>
#include <vigine/unittest/unittest.h>
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

VIGINE_TEST(SecretWipeTest, WipesArrayAtEndOfScope)
{
    Secret secret = filled();
    {
        const SecretWipe wipe{secret};
        VIGINE_EXPECT_FALSE(allZero(secret.data(), secret.size()));
    }
    VIGINE_EXPECT_TRUE(allZero(secret.data(), secret.size()));
}

VIGINE_TEST(SecretWipeTest, WipesOnEarlyReturn)
{
    Secret secret = filled();
    VIGINE_EXPECT_FALSE(useThenReturnEarly(secret, true));
    VIGINE_EXPECT_TRUE(allZero(secret.data(), secret.size()));
}

VIGINE_TEST(SecretWipeTest, WipesOnNormalReturn)
{
    Secret secret = filled();
    VIGINE_EXPECT_TRUE(useThenReturnEarly(secret, false));
    VIGINE_EXPECT_TRUE(allZero(secret.data(), secret.size()));
}

VIGINE_TEST(SecretWipeTest, WipesWhenExceptionUnwinds)
{
    Secret secret = filled();
    VIGINE_EXPECT_THROW(throwsWhileHolding(secret), std::runtime_error);
    VIGINE_EXPECT_TRUE(allZero(secret.data(), secret.size()));
}

VIGINE_TEST(SecretWipeTest, WipesWholeVectorIncludingGrownContents)
{
    std::vector<std::byte> transcript;
    transcript.reserve(64);
    {
        const SecretWipe wipe{transcript};
        transcript.assign(48, std::byte{0x3C});
        VIGINE_EXPECT_EQ(transcript.size(), 48U);
    }
    VIGINE_EXPECT_TRUE(allZero(transcript.data(), transcript.size()));
}
