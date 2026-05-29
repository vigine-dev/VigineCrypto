#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace vigine::crypto
{

// A self-signed certificate + private key in PEM, for tests and local/dev
// servers.
// ENCAP EXEMPT: pure value aggregate
struct SelfSignedCert
{
    std::string certPem;
    std::string keyPem;
};

[[nodiscard]] SelfSignedCert generateSelfSignedCert(std::string_view hostname);

// TLS 1.3 stream over an already-connected socket (the native handle passed
// as a uintptr_t). Client or server. All OpenSSL SSL_* types stay hidden.
// TLS below 1.3 is refused, and the client always verifies the server's
// certificate and hostname -- there is no "skip verification" knob.
class TlsStream
{
public:
    // Client handshake. If trustedCertPem is non-empty it is the sole trusted
    // root (self-signed / pinning); otherwise the system trust store is used.
    [[nodiscard]] static TlsStream connectClient(std::uintptr_t   connectedSocket,
                                                 std::string_view expectedHostname,
                                                 std::string_view trustedCertPem = {});

    // Server handshake with a PEM certificate + private key.
    [[nodiscard]] static TlsStream acceptServer(std::uintptr_t connectedSocket,
                                                std::string_view certPem, std::string_view keyPem);

    ~TlsStream();
    TlsStream(TlsStream &&other) noexcept;
    TlsStream &operator=(TlsStream &&other) noexcept;
    TlsStream(const TlsStream &)            = delete;
    TlsStream &operator=(const TlsStream &) = delete;

    // True when the handshake succeeded.
    [[nodiscard]] bool ok() const noexcept;

    [[nodiscard]] bool writeAll(std::span<const std::byte> data) noexcept;
    [[nodiscard]] bool readExact(std::span<std::byte> data) noexcept;
    void               shutdown() noexcept;

private:
    struct State;
    explicit TlsStream(std::unique_ptr<State> state) noexcept;
    std::unique_ptr<State> _state;
};

}
