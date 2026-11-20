#pragma once

#include <cstddef>
#include <span>
#include "vigine/crypto/viginecrypto_export.h"

namespace vigine::crypto
{

// Compares in time that does not depend on where the spans differ; different sizes are unequal.
[[nodiscard]] VIGINECRYPTO_API bool equalConstantTime(std::span<const std::byte> left, std::span<const std::byte> right) noexcept;

} // namespace vigine::crypto
