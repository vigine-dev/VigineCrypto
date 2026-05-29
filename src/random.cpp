#include "vigine/crypto/random.h"

#include <openssl/rand.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>

namespace vigine::crypto
{

void randomBytes(std::span<std::byte> out)
{
    auto       *cursor    = reinterpret_cast<unsigned char *>(out.data());
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
        cursor += chunk;
        remaining -= static_cast<std::size_t>(chunk);
    }
}

}
