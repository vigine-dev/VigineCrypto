#include "vigine/crypto/compare.h"

#include <openssl/crypto.h>

namespace vigine::crypto
{

bool equalConstantTime(std::span<const std::byte> left, std::span<const std::byte> right) noexcept
{
    if (left.size() != right.size())
        return false;
    if (left.empty())
        return true;
    return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

} // namespace vigine::crypto
