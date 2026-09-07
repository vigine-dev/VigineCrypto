#include "vigine/crypto/random.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <openssl/rand.h>

namespace vigine::crypto
{

namespace
{

void runCsprngSelfCheck()
{
    // RAND_status() reports 1 once the DRBG has pulled enough entropy to be
    // safe to draw from. If it has not, RAND_poll() asks the backend to gather
    // entropy from the OS source; we then re-check rather than trust the poll.
    if (RAND_status() != 1)
    {
        if (RAND_poll() != 1 || RAND_status() != 1)
        {
            std::fprintf(stderr, "[crypto.random.csprng_unseeded] OpenSSL CSPRNG is not seeded "
                                 "and entropy polling failed\n");
            std::abort();
        }
    }

    // A seeded status is necessary but prove an actual draw succeeds, so a
    // broken backend cannot pass the check yet fail every real request.
    unsigned char probe[32];
    if (RAND_bytes(probe, static_cast<int>(sizeof(probe))) != 1)
    {
        std::fprintf(stderr, "[crypto.random.csprng_probe_failure] OpenSSL CSPRNG reports seeded "
                             "but a probe draw failed\n");
        std::abort();
    }
}

} // namespace

void ensureCsprngReady()
{
    static std::once_flag checkOnce;
    std::call_once(checkOnce, runCsprngSelfCheck);
}

void randomBytes(std::span<std::byte> out)
{
    ensureCsprngReady();

    auto *cursor          = reinterpret_cast<unsigned char *>(out.data());
    std::size_t remaining = out.size();

    // RAND_bytes takes an int length; chunk so an oversized span can never
    // overflow the conversion. Crypto buffers are tiny in practice.
    while (remaining > 0)
    {
        const int chunk = static_cast<int>(std::min<std::size_t>(remaining, 1u << 20));
        if (RAND_bytes(cursor, chunk) != 1)
        {
            std::fprintf(stderr, "[crypto.random.rand_bytes_failure] CSPRNG backend failed\n");
            std::abort();
        }
        cursor    += chunk;
        remaining -= static_cast<std::size_t>(chunk);
    }
}

} // namespace vigine::crypto
