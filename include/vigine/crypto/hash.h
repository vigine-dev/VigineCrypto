#pragma once

#include <array>
#include <cstddef>
#include <memory>
#include <span>

namespace vigine::crypto
{

inline constexpr std::size_t kBlake3HashSize = 32;

// One-shot BLAKE3 hash. The result is byte-identical across platforms, which
// is what content-addressing (commit ids, payload fingerprints) relies on.
[[nodiscard]] std::array<std::byte, kBlake3HashSize> blake3(std::span<const std::byte> input);

// Incremental BLAKE3 hashing for inputs assembled from several pieces. The
// backend hasher state is hidden behind a pointer so this header pulls in no
// backend type.
class Blake3Hasher
{
  public:
    Blake3Hasher();
    ~Blake3Hasher();
    Blake3Hasher(Blake3Hasher &&) noexcept;
    Blake3Hasher &operator=(Blake3Hasher &&) noexcept;
    Blake3Hasher(const Blake3Hasher &)            = delete;
    Blake3Hasher &operator=(const Blake3Hasher &) = delete;

    void update(std::span<const std::byte> input);
    [[nodiscard]] std::array<std::byte, kBlake3HashSize> finalize() const;

  private:
    struct State;
    std::unique_ptr<State> _state;
};

} // namespace vigine::crypto
