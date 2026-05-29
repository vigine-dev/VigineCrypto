#pragma once

#include <cstddef>
#include <span>

namespace vigine::crypto
{

// Fills the buffer with cryptographically secure random bytes. There is no
// weaker fallback and no seeding knob -- a single vetted backend is used,
// and a failure (which it does not produce under normal operation) is fatal.
void randomBytes(std::span<std::byte> out);

}
