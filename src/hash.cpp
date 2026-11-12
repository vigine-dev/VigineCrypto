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

namespace
{

class Blake3Hasher final : public IHasher
{
  public:
    Blake3Hasher() { blake3_hasher_init(&_hasher); }

    void update(std::span<const std::byte> input) override
    {
        blake3_hasher_update(&_hasher, input.data(), input.size());
    }

    std::array<std::byte, kBlake3HashSize> finalize() const override
    {
        std::array<std::byte, kBlake3HashSize> out{};
        blake3_hasher_finalize(&_hasher, reinterpret_cast<std::uint8_t *>(out.data()), out.size());
        return out;
    }

  private:
    blake3_hasher _hasher;
};

} // namespace

std::unique_ptr<IHasher> createBlake3Hasher() { return std::make_unique<Blake3Hasher>(); }

} // namespace vigine::crypto
