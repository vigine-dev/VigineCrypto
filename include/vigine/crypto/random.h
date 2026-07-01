#pragma once

#include <cstddef>
#include <span>

namespace vigine::crypto
{

// Verifies the CSPRNG backend is seeded and drawable before any secret-grade
// randomness is produced. If the OpenSSL DRBG is not yet seeded it polls the
// entropy source once and re-checks; an unseeded backend or a failing probe
// draw is fatal. Runs automatically before the first randomBytes draw so no
// caller can observe an unverified entropy source; call it explicitly at
// startup to surface a broken source eagerly. Idempotent -- the check runs once.
void ensureCsprngReady();

// Fills the buffer with cryptographically secure random bytes. There is no
// weaker fallback and no seeding knob -- a single vetted backend is used,
// and a failure (which it does not produce under normal operation) is fatal.
void randomBytes(std::span<std::byte> out);

}
