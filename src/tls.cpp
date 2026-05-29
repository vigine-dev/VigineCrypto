#include "vigine/crypto/tls.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string>
#include <utility>

namespace vigine::crypto
{

struct TlsStream::State
{
    SSL_CTX *ctx{nullptr};
    SSL     *ssl{nullptr};
    bool     ok{false};

    ~State()
    {
        if (ssl != nullptr)
            SSL_free(ssl);
        if (ctx != nullptr)
            SSL_CTX_free(ctx);
    }
};

namespace
{
// POSIX file descriptors fit in int and SSL_set_fd takes int, so this narrowing
// is correct on the implemented macOS/Linux target. A Windows SOCKET is a
// UINT_PTR that can exceed INT_MAX; the Windows TLS backend is a follow-on and
// must convert the handle deliberately rather than reuse this helper.
int nativeFd(std::uintptr_t handle) noexcept
{
    return static_cast<int>(static_cast<std::intptr_t>(handle));
}
}

SelfSignedCert generateSelfSignedCert(std::string_view hostname)
{
    SelfSignedCert result;

    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<std::size_t>(2048));
    if (pkey == nullptr)
        return result;

    X509 *certificate = X509_new();
    if (certificate == nullptr)
    {
        EVP_PKEY_free(pkey);
        return result;
    }

    X509_set_version(certificate, 2); // X.509 v3
    ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1);
    X509_gmtime_adj(X509_getm_notBefore(certificate), 0);
    X509_gmtime_adj(X509_getm_notAfter(certificate), 60L * 60 * 24 * 365);
    X509_set_pubkey(certificate, pkey);

    const std::string host(hostname);
    X509_NAME        *subject = X509_get_subject_name(certificate);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(host.c_str()), -1, -1, 0);
    X509_set_issuer_name(certificate, subject); // self-signed: issuer == subject

    // Modern verifiers match the hostname against subjectAltName, not CN.
    X509V3_CTX v3ctx;
    X509V3_set_ctx(&v3ctx, certificate, certificate, nullptr, nullptr, 0);
    const std::string san = "DNS:" + host;
    if (X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_subject_alt_name, san.c_str()))
    {
        X509_add_ext(certificate, ext, -1);
        X509_EXTENSION_free(ext);
    }

    if (X509_sign(certificate, pkey, EVP_sha256()) == 0)
    {
        X509_free(certificate);
        EVP_PKEY_free(pkey);
        return result; // an unsigned cert is unusable -- honour the empty-on-failure contract
    }

    BIO *certBio = BIO_new(BIO_s_mem());
    BIO *keyBio  = BIO_new(BIO_s_mem());
    if (certBio != nullptr && keyBio != nullptr &&
        PEM_write_bio_X509(certBio, certificate) == 1 &&
        PEM_write_bio_PrivateKey(keyBio, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1)
    {
        char      *certData = nullptr;
        const long certLen  = BIO_get_mem_data(certBio, &certData);
        char      *keyData  = nullptr;
        const long keyLen   = BIO_get_mem_data(keyBio, &keyData);
        if (certData != nullptr && certLen > 0 && keyData != nullptr && keyLen > 0)
        {
            result.certPem.assign(certData, static_cast<std::size_t>(certLen));
            result.keyPem.assign(keyData, static_cast<std::size_t>(keyLen));
        }
        // The key BIO buffer held the unencrypted private key; wipe it.
        if (keyData != nullptr && keyLen > 0)
            OPENSSL_cleanse(keyData, static_cast<std::size_t>(keyLen));
    }

    if (certBio != nullptr)
        BIO_free(certBio);
    if (keyBio != nullptr)
        BIO_free(keyBio);
    X509_free(certificate);
    EVP_PKEY_free(pkey);
    return result;
}

TlsStream::TlsStream(std::unique_ptr<State> state) noexcept : _state(std::move(state)) {}
TlsStream::~TlsStream()                              = default;
TlsStream::TlsStream(TlsStream &&) noexcept          = default;
TlsStream &TlsStream::operator=(TlsStream &&) noexcept = default;

TlsStream TlsStream::connectClient(std::uintptr_t connectedSocket, std::string_view expectedHostname,
                                   std::string_view trustedCertPem)
{
    auto state = std::make_unique<State>();

    // An empty expected hostname cannot be verified; refuse rather than fall
    // through to accepting any chain-valid certificate.
    const std::string host(expectedHostname);
    if (host.empty())
        return TlsStream(std::move(state));

    state->ctx = SSL_CTX_new(TLS_client_method());
    if (state->ctx == nullptr)
        return TlsStream(std::move(state));

    if (SSL_CTX_set_min_proto_version(state->ctx, TLS1_3_VERSION) != 1)
        return TlsStream(std::move(state));

    if (!trustedCertPem.empty())
    {
        BIO  *bio = BIO_new_mem_buf(trustedCertPem.data(), static_cast<int>(trustedCertPem.size()));
        X509 *trusted = (bio != nullptr) ? PEM_read_bio_X509(bio, nullptr, nullptr, nullptr) : nullptr;
        if (trusted != nullptr)
        {
            X509_STORE_add_cert(SSL_CTX_get_cert_store(state->ctx), trusted);
            X509_free(trusted);
        }
        if (bio != nullptr)
            BIO_free(bio);
        // A pin was requested but did not parse -- do not silently trust nothing.
        if (trusted == nullptr)
            return TlsStream(std::move(state));
    }
    else if (SSL_CTX_set_default_verify_paths(state->ctx) != 1)
    {
        return TlsStream(std::move(state));
    }
    SSL_CTX_set_verify(state->ctx, SSL_VERIFY_PEER, nullptr);

    state->ssl = SSL_new(state->ctx);
    if (state->ssl == nullptr)
        return TlsStream(std::move(state));

    SSL_set_fd(state->ssl, nativeFd(connectedSocket));
    SSL_set_tlsext_host_name(state->ssl, host.c_str()); // SNI
    SSL_set_hostflags(state->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    // Arming hostname verification MUST succeed; otherwise the peer certificate
    // would be chain-checked but never matched against the expected hostname.
    if (SSL_set1_host(state->ssl, host.c_str()) != 1)
        return TlsStream(std::move(state));

    state->ok = (SSL_connect(state->ssl) == 1);
    return TlsStream(std::move(state));
}

TlsStream TlsStream::acceptServer(std::uintptr_t connectedSocket, std::string_view certPem,
                                  std::string_view keyPem)
{
    auto state = std::make_unique<State>();
    state->ctx = SSL_CTX_new(TLS_server_method());
    if (state->ctx == nullptr)
        return TlsStream(std::move(state));

    if (SSL_CTX_set_min_proto_version(state->ctx, TLS1_3_VERSION) != 1)
        return TlsStream(std::move(state));

    BIO  *certBio     = BIO_new_mem_buf(certPem.data(), static_cast<int>(certPem.size()));
    X509 *certificate = (certBio != nullptr) ? PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr) : nullptr;
    const bool certOk = certificate != nullptr && SSL_CTX_use_certificate(state->ctx, certificate) == 1;
    if (certificate != nullptr)
        X509_free(certificate);
    if (certBio != nullptr)
        BIO_free(certBio);
    if (!certOk)
        return TlsStream(std::move(state));

    BIO      *keyBio = BIO_new_mem_buf(keyPem.data(), static_cast<int>(keyPem.size()));
    EVP_PKEY *key    = (keyBio != nullptr) ? PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr) : nullptr;
    const bool keyOk = key != nullptr && SSL_CTX_use_PrivateKey(state->ctx, key) == 1;
    if (key != nullptr)
        EVP_PKEY_free(key);
    if (keyBio != nullptr)
        BIO_free(keyBio);
    if (!keyOk)
        return TlsStream(std::move(state));

    // Reject a key that does not match the certificate before handshaking.
    if (SSL_CTX_check_private_key(state->ctx) != 1)
        return TlsStream(std::move(state));

    state->ssl = SSL_new(state->ctx);
    if (state->ssl != nullptr)
    {
        SSL_set_fd(state->ssl, nativeFd(connectedSocket));
        state->ok = (SSL_accept(state->ssl) == 1);
    }
    return TlsStream(std::move(state));
}

bool TlsStream::ok() const noexcept
{
    return _state && _state->ok;
}

bool TlsStream::writeAll(std::span<const std::byte> data) noexcept
{
    if (!ok())
        return false;
    std::size_t offset = 0;
    while (offset < data.size())
    {
        const int written = SSL_write(_state->ssl, data.data() + offset,
                                      static_cast<int>(data.size() - offset));
        if (written <= 0)
            return false;
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

bool TlsStream::readExact(std::span<std::byte> data) noexcept
{
    if (!ok())
        return false;
    std::size_t offset = 0;
    while (offset < data.size())
    {
        const int read = SSL_read(_state->ssl, data.data() + offset,
                                  static_cast<int>(data.size() - offset));
        if (read <= 0)
            return false;
        offset += static_cast<std::size_t>(read);
    }
    return true;
}

void TlsStream::shutdown() noexcept
{
    if (_state && _state->ssl != nullptr)
        SSL_shutdown(_state->ssl);
}

}
