#pragma once

#include <cstddef>
#include <span>
#include <vector>

namespace vigine::crypto
{

// HKDF-SHA256 (RFC 5869): derive `outLength` bytes of key material from input
// keying material `secret`, an optional `salt` (may be empty), and a context
// `info` (may be empty). Returns the derived bytes, or an EMPTY vector on failure
// -- notably when `outLength` is 0 or exceeds HKDF's ceiling of 255*HashLen
// (= 8160 bytes for SHA-256), or when `secret` is empty. Callers must treat an
// empty result as an error.
[[nodiscard]] std::vector<std::byte> hkdfSha256(std::span<const std::byte> secret,
                                                std::span<const std::byte> salt,
                                                std::span<const std::byte> info,
                                                std::size_t outLength);

} // namespace vigine::crypto
