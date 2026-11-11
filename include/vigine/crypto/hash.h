#pragma once

#include <array>
#include <cstddef>
#include <memory>
#include <span>

#include "vigine/crypto/viginecrypto_export.h"

namespace vigine::crypto
{

inline constexpr std::size_t kBlake3HashSize = 32;

// One-shot BLAKE3 hash. The result is byte-identical across platforms, which
// is what content-addressing (commit ids, payload fingerprints) relies on.
[[nodiscard]] VIGINECRYPTO_API std::array<std::byte, kBlake3HashSize> blake3(std::span<const std::byte> input);

// Incremental BLAKE3 hashing for inputs assembled from several pieces. The
// backend hasher state lives inside the library; this interface names no backend type.
class IHasher
{
  public:
    virtual ~IHasher() = default;

    virtual void update(std::span<const std::byte> input)                         = 0;
    [[nodiscard]] virtual std::array<std::byte, kBlake3HashSize> finalize() const = 0;
};

[[nodiscard]] VIGINECRYPTO_API std::unique_ptr<IHasher> createBlake3Hasher();

} // namespace vigine::crypto
