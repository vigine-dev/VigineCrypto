#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include "vigine/crypto/viginecrypto_export.h"

namespace vigine::crypto
{

// A self-signed certificate + private key in PEM, for tests and local/dev
// servers; both empty when generation failed.
class SelfSignedCert
{
  public:
    SelfSignedCert() = default;
    SelfSignedCert(std::string certPem, std::string keyPem)
        : _certPem(std::move(certPem)), _keyPem(std::move(keyPem))
    {
    }

    [[nodiscard]] const std::string &certPem() const { return _certPem; }
    [[nodiscard]] const std::string &keyPem() const { return _keyPem; }

  private:
    std::string _certPem;
    std::string _keyPem;
};

[[nodiscard]] VIGINECRYPTO_API SelfSignedCert generateSelfSignedCert(std::string_view hostname);

// TLS 1.3 stream over an already-connected socket (the native handle passed
// as a uintptr_t). Client or server. All OpenSSL SSL_* types stay hidden.
// TLS below 1.3 is refused, and the client always verifies the server's
// certificate and hostname -- there is no "skip verification" knob.
class ITlsStream
{
  public:
    virtual ~ITlsStream() = default;

    // True when the handshake succeeded.
    [[nodiscard]] virtual bool ok() const noexcept = 0;

    // Why the connect failed; empty when it succeeded.
    [[nodiscard]] virtual const std::string &failureReason() const noexcept = 0;

    [[nodiscard]] virtual bool writeAll(std::span<const std::byte> data) noexcept = 0;
    [[nodiscard]] virtual bool readExact(std::span<std::byte> data) noexcept      = 0;
    virtual void shutdown() noexcept                                              = 0;
};

// Client handshake. If trustedCertPem is non-empty it is the sole trusted
// root (self-signed / pinning); else if trustedRootsFile (a PEM file of
// roots) is non-empty it is the sole trust; otherwise the system roots are
// used (macOS /etc/ssl/cert.pem, the Linux distro bundle, the Windows ROOT
// store). Always answers a stream: when no root can be loaded or the
// handshake fails, ok() is false and failureReason() says why.
[[nodiscard]] VIGINECRYPTO_API std::unique_ptr<ITlsStream>
connectTlsClient(std::uintptr_t connectedSocket, std::string_view expectedHostname,
                 std::string_view trustedCertPem = {}, std::string_view trustedRootsFile = {});

// Server handshake with a PEM certificate + private key; a stream whose ok() says how it went.
[[nodiscard]] VIGINECRYPTO_API std::unique_ptr<ITlsStream>
acceptTlsServer(std::uintptr_t connectedSocket, std::string_view certPem, std::string_view keyPem);

// How many system root certificates this machine offers (0 when none load).
[[nodiscard]] VIGINECRYPTO_API std::size_t tlsSystemRootCount();

} // namespace vigine::crypto
