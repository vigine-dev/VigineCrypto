#include "vigine/crypto/hash.h"

#include <blake3.h>

#include <cstdint>

namespace vigine::crypto
{

std::array<std::byte, kBlake3HashSize> blake3(std::span<const std::byte> input)
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input.data(), input.size());

    std::array<std::byte, kBlake3HashSize> out{};
    blake3_hasher_finalize(&hasher, reinterpret_cast<std::uint8_t *>(out.data()), out.size());
    return out;
}

struct Blake3Hasher::State
{
    blake3_hasher hasher;
};

Blake3Hasher::Blake3Hasher() : _state(std::make_unique<State>())
{
    blake3_hasher_init(&_state->hasher);
}

Blake3Hasher::~Blake3Hasher()                                  = default;
Blake3Hasher::Blake3Hasher(Blake3Hasher &&) noexcept           = default;
Blake3Hasher &Blake3Hasher::operator=(Blake3Hasher &&) noexcept = default;

void Blake3Hasher::update(std::span<const std::byte> input)
{
    blake3_hasher_update(&_state->hasher, input.data(), input.size());
}

std::array<std::byte, kBlake3HashSize> Blake3Hasher::finalize() const
{
    std::array<std::byte, kBlake3HashSize> out{};
    blake3_hasher_finalize(&_state->hasher, reinterpret_cast<std::uint8_t *>(out.data()), out.size());
    return out;
}

}
