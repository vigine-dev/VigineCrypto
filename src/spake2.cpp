#include "cryptodetail.h"

#include "vigine/crypto/hkdf.h"
#include "vigine/crypto/spake2.h"

#include <cstring>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <string>
#include <utility>
#include <vector>

namespace vigine::crypto
{
namespace
{

using BnPtr    = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
using BnCtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using GroupPtr = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_clear_free)>;

// The points M and N for P-256 (RFC 9382, section 6), compressed.
constexpr unsigned char kM[33] = {0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d,
                                  0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3,
                                  0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f};
constexpr unsigned char kN[33] = {0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d,
                                  0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01,
                                  0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49};

constexpr std::string_view kConfirmationInfo = "ConfirmationKeys";

GroupPtr p256()
{
    GroupPtr group{EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), EC_GROUP_free};
    if (!group)
        detail::fatal("spake2");
    return group;
}

BnPtr bignum() { return BnPtr{BN_new(), BN_clear_free}; }

PointPtr point(const EC_GROUP *group) { return PointPtr{EC_POINT_new(group), EC_POINT_clear_free}; }

const unsigned char *bytesOf(std::span<const std::byte> bytes)
{
    return reinterpret_cast<const unsigned char *>(bytes.data());
}

// A point of the curve from its encoding; null when the bytes name none, or the point at infinity.
PointPtr decodePoint(const EC_GROUP *group, std::span<const std::byte> bytes, BN_CTX *ctx)
{
    PointPtr decoded = point(group);
    if (!decoded ||
        EC_POINT_oct2point(group, decoded.get(), bytesOf(bytes), bytes.size(), ctx) != 1 ||
        EC_POINT_is_at_infinity(group, decoded.get()) == 1 ||
        EC_POINT_is_on_curve(group, decoded.get(), ctx) != 1)
        return PointPtr{nullptr, EC_POINT_clear_free};
    return decoded;
}

std::array<std::byte, kSpake2ShareSize> encodePoint(const EC_GROUP *group, const EC_POINT *value,
                                                    BN_CTX *ctx)
{
    std::array<std::byte, kSpake2ShareSize> encoded{};
    if (EC_POINT_point2oct(group, value, POINT_CONVERSION_UNCOMPRESSED,
                           reinterpret_cast<unsigned char *>(encoded.data()), encoded.size(),
                           ctx) != encoded.size())
        detail::fatal("spake2");
    return encoded;
}

// A 32-byte big-endian number below the group order; null when it is zero or not below it.
BnPtr scalarFrom(const EC_GROUP *group, std::span<const std::byte> bytes, bool zeroAllowed)
{
    BnPtr value = bignum();
    if (!value || BN_bin2bn(bytesOf(bytes), static_cast<int>(bytes.size()), value.get()) == nullptr)
        detail::fatal("spake2");
    if (BN_cmp(value.get(), EC_GROUP_get0_order(group)) >= 0 ||
        (!zeroAllowed && BN_is_zero(value.get()) == 1))
        return BnPtr{nullptr, BN_clear_free};
    return value;
}

void appendLength(std::vector<std::byte> &out, std::size_t length)
{
    for (int index = 0; index < 8; ++index)
        out.push_back(
            static_cast<std::byte>((static_cast<std::uint64_t>(length) >> (8 * index)) & 0xFFu));
}

void appendField(std::vector<std::byte> &out, std::span<const std::byte> field)
{
    appendLength(out, field.size());
    out.insert(out.end(), field.begin(), field.end());
}

std::array<std::byte, 32> sha256(std::span<const std::byte> input)
{
    std::array<std::byte, 32> digest{};
    unsigned int length = 0;
    if (EVP_Digest(input.data(), input.size(), reinterpret_cast<unsigned char *>(digest.data()),
                   &length, EVP_sha256(), nullptr) != 1 ||
        length != digest.size())
        detail::fatal("spake2");
    return digest;
}

std::array<std::byte, kSpake2ConfirmationSize> hmacSha256(std::span<const std::byte> key,
                                                          std::span<const std::byte> data)
{
    std::array<std::byte, kSpake2ConfirmationSize> mac{};
    unsigned int length = 0;
    if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), bytesOf(data), data.size(),
             reinterpret_cast<unsigned char *>(mac.data()), &length) == nullptr ||
        length != mac.size())
        detail::fatal("spake2");
    return mac;
}

} // namespace

struct Spake2::State
{
    Spake2Role role{Spake2Role::A};
    std::array<std::byte, kSpake2ScalarSize> password{};
    std::vector<std::byte> identityA;
    std::vector<std::byte> identityB;
    std::array<std::byte, kSpake2ScalarSize> scalar{};
    std::array<std::byte, kSpake2ShareSize> share{};

    ~State()
    {
        OPENSSL_cleanse(scalar.data(), scalar.size());
        OPENSSL_cleanse(password.data(), password.size());
    }
};

Spake2::Spake2(std::unique_ptr<State> state) : _state(std::move(state)) {}
Spake2::Spake2(Spake2 &&) noexcept            = default;
Spake2 &Spake2::operator=(Spake2 &&) noexcept = default;
Spake2::~Spake2()                             = default;

std::optional<Spake2> Spake2::begin(Spake2Role role, std::span<const std::byte> password,
                                    std::span<const std::byte> identityA,
                                    std::span<const std::byte> identityB)
{
    const GroupPtr group = p256();
    BnPtr secret         = bignum();
    if (!secret)
        detail::fatal("spake2");
    do
    {
        if (BN_rand_range(secret.get(), EC_GROUP_get0_order(group.get())) != 1)
            detail::fatal("spake2");
    } while (BN_is_zero(secret.get()) == 1);
    std::array<std::byte, kSpake2ScalarSize> scalar{};
    if (BN_bn2binpad(secret.get(), reinterpret_cast<unsigned char *>(scalar.data()),
                     static_cast<int>(scalar.size())) != static_cast<int>(scalar.size()))
        detail::fatal("spake2");
    std::optional<Spake2> exchange = beginWithScalar(role, password, identityA, identityB, scalar);
    OPENSSL_cleanse(scalar.data(), scalar.size());
    return exchange;
}

std::optional<Spake2> Spake2::beginWithScalar(Spake2Role role, std::span<const std::byte> password,
                                              std::span<const std::byte> identityA,
                                              std::span<const std::byte> identityB,
                                              std::span<const std::byte, kSpake2ScalarSize> scalar)
{
    const GroupPtr group = p256();
    const BnCtxPtr ctx{BN_CTX_new(), BN_CTX_free};
    if (!ctx)
        detail::fatal("spake2");
    const BnPtr w      = scalarFrom(group.get(), password, true);
    const BnPtr secret = scalarFrom(group.get(), scalar, false);
    if (!w || !secret || password.size() != kSpake2ScalarSize)
        return std::nullopt;

    // pA = x*G + w*M; pB = y*G + w*N.
    const PointPtr blind = decodePoint(group.get(),
                                       role == Spake2Role::A ? std::as_bytes(std::span{kM})
                                                             : std::as_bytes(std::span{kN}),
                                       ctx.get());
    PointPtr shared      = point(group.get());
    if (!blind || !shared ||
        EC_POINT_mul(group.get(), shared.get(), secret.get(), blind.get(), w.get(), ctx.get()) != 1)
        detail::fatal("spake2");

    auto state  = std::make_unique<State>();
    state->role = role;
    state->identityA.assign(identityA.begin(), identityA.end());
    state->identityB.assign(identityB.begin(), identityB.end());
    std::memcpy(state->password.data(), password.data(), password.size());
    std::memcpy(state->scalar.data(), scalar.data(), scalar.size());
    state->share = encodePoint(group.get(), shared.get(), ctx.get());
    return Spake2{std::move(state)};
}

std::span<const std::byte, kSpake2ShareSize> Spake2::share() const { return _state->share; }

std::optional<Spake2Outcome> Spake2::finish(std::span<const std::byte> peerShare) const
{
    const GroupPtr group = p256();
    const BnCtxPtr ctx{BN_CTX_new(), BN_CTX_free};
    if (!ctx)
        detail::fatal("spake2");
    const PointPtr peer = decodePoint(group.get(), peerShare, ctx.get());
    if (!peer)
        return std::nullopt;
    const BnPtr w      = scalarFrom(group.get(), _state->password, true);
    const BnPtr secret = scalarFrom(group.get(), _state->scalar, false);
    if (!w || !secret)
        return std::nullopt;

    // K = x*(pB - w*N) for A, y*(pA - w*M) for B; the cofactor of P-256 is 1.
    const bool sideA = _state->role == Spake2Role::A;
    const PointPtr peerBlind =
        decodePoint(group.get(),
                    sideA ? std::as_bytes(std::span{kN}) : std::as_bytes(std::span{kM}), ctx.get());
    PointPtr unblinded = point(group.get());
    PointPtr key       = point(group.get());
    if (!peerBlind || !unblinded || !key ||
        EC_POINT_mul(group.get(), unblinded.get(), nullptr, peerBlind.get(), w.get(), ctx.get()) !=
            1 ||
        EC_POINT_invert(group.get(), unblinded.get(), ctx.get()) != 1 ||
        EC_POINT_add(group.get(), unblinded.get(), peer.get(), unblinded.get(), ctx.get()) != 1 ||
        EC_POINT_mul(group.get(), key.get(), nullptr, unblinded.get(), secret.get(), ctx.get()) !=
            1)
        detail::fatal("spake2");
    if (EC_POINT_is_at_infinity(group.get(), key.get()) == 1)
        return std::nullopt;
    const std::array<std::byte, kSpake2ShareSize> keyBytes =
        encodePoint(group.get(), key.get(), ctx.get());

    // TT = len(A)||A || len(B)||B || len(pA)||pA || len(pB)||pB || len(K)||K || len(w)||w.
    const std::span<const std::byte> ownShare{_state->share};
    std::vector<std::byte> transcript;
    appendField(transcript, _state->identityA);
    appendField(transcript, _state->identityB);
    appendField(transcript, sideA ? ownShare : peerShare);
    appendField(transcript, sideA ? peerShare : ownShare);
    appendField(transcript, keyBytes);
    appendField(transcript, _state->password);

    std::array<std::byte, 32> digest = sha256(transcript);
    const std::span<const std::byte> ka{digest.data() + kSpake2KeySize, kSpake2KeySize};
    std::vector<std::byte> confirmationKeys =
        hkdfSha256(ka, {}, std::as_bytes(std::span{kConfirmationInfo}), 2 * kSpake2KeySize);
    if (confirmationKeys.size() != 2 * kSpake2KeySize)
        detail::fatal("spake2");

    Spake2Outcome outcome;
    std::memcpy(outcome.sharedKey.data(), digest.data(), kSpake2KeySize);
    outcome.confirmationA =
        hmacSha256(std::span{confirmationKeys.data(), kSpake2KeySize}, transcript);
    outcome.confirmationB =
        hmacSha256(std::span{confirmationKeys.data() + kSpake2KeySize, kSpake2KeySize}, transcript);
    OPENSSL_cleanse(digest.data(), digest.size());
    OPENSSL_cleanse(confirmationKeys.data(), confirmationKeys.size());
    return outcome;
}

std::array<std::byte, kSpake2ScalarSize> spake2PasswordScalar(std::string_view domain,
                                                              std::string_view code)
{
    std::vector<std::byte> input;
    for (const char character : domain)
        input.push_back(static_cast<std::byte>(character));
    input.push_back(std::byte{0});
    for (const char character : code)
        input.push_back(static_cast<std::byte>(character));
    std::array<std::byte, 32> digest = sha256(input);
    OPENSSL_cleanse(input.data(), input.size());

    const GroupPtr group = p256();
    const BnCtxPtr ctx{BN_CTX_new(), BN_CTX_free};
    BnPtr value = bignum();
    if (!ctx || !value ||
        BN_bin2bn(bytesOf(digest), static_cast<int>(digest.size()), value.get()) == nullptr ||
        BN_nnmod(value.get(), value.get(), EC_GROUP_get0_order(group.get()), ctx.get()) != 1)
        detail::fatal("spake2");
    std::array<std::byte, kSpake2ScalarSize> scalar{};
    if (BN_bn2binpad(value.get(), reinterpret_cast<unsigned char *>(scalar.data()),
                     static_cast<int>(scalar.size())) != static_cast<int>(scalar.size()))
        detail::fatal("spake2");
    OPENSSL_cleanse(digest.data(), digest.size());
    return scalar;
}

bool spake2ConfirmationsMatch(std::span<const std::byte, kSpake2ConfirmationSize> left,
                              std::span<const std::byte, kSpake2ConfirmationSize> right)
{
    return CRYPTO_memcmp(left.data(), right.data(), kSpake2ConfirmationSize) == 0;
}

} // namespace vigine::crypto
