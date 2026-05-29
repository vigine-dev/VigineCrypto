#include "vigine/crypto/tls.h"

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

    X509_sign(certificate, pkey, EVP_sha256());

    BIO *certBio = BIO_new(BIO_s_mem());
    BIO *keyBio  = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(certBio, certificate);
    PEM_write_bio_PrivateKey(keyBio, pkey, nullptr, nullptr, 0, nullptr, nullptr);

    char *certData = nullptr;
    long  certLen  = BIO_get_mem_data(certBio, &certData);
    result.certPem.assign(certData, static_cast<std::size_t>(certLen));
    char *keyData = nullptr;
    long  keyLen  = BIO_get_mem_data(keyBio, &keyData);
    result.keyPem.assign(keyData, static_cast<std::size_t>(keyLen));

    BIO_free(certBio);
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
    state->ctx = SSL_CTX_new(TLS_client_method());
    if (state->ctx != nullptr)
    {
        SSL_CTX_set_min_proto_version(state->ctx, TLS1_3_VERSION);

        if (!trustedCertPem.empty())
        {
            BIO *bio = BIO_new_mem_buf(trustedCertPem.data(), static_cast<int>(trustedCertPem.size()));
            if (X509 *trusted = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr))
            {
                X509_STORE_add_cert(SSL_CTX_get_cert_store(state->ctx), trusted);
                X509_free(trusted);
            }
            BIO_free(bio);
        }
        else
        {
            SSL_CTX_set_default_verify_paths(state->ctx);
        }
        SSL_CTX_set_verify(state->ctx, SSL_VERIFY_PEER, nullptr);

        state->ssl = SSL_new(state->ctx);
        if (state->ssl != nullptr)
        {
            const std::string host(expectedHostname);
            SSL_set_fd(state->ssl, nativeFd(connectedSocket));
            SSL_set_tlsext_host_name(state->ssl, host.c_str()); // SNI
            SSL_set1_host(state->ssl, host.c_str());            // verified hostname
            state->ok = (SSL_connect(state->ssl) == 1);
        }
    }
    return TlsStream(std::move(state));
}

TlsStream TlsStream::acceptServer(std::uintptr_t connectedSocket, std::string_view certPem,
                                  std::string_view keyPem)
{
    auto state = std::make_unique<State>();
    state->ctx = SSL_CTX_new(TLS_server_method());
    if (state->ctx != nullptr)
    {
        SSL_CTX_set_min_proto_version(state->ctx, TLS1_3_VERSION);

        BIO *certBio = BIO_new_mem_buf(certPem.data(), static_cast<int>(certPem.size()));
        if (X509 *certificate = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr))
        {
            SSL_CTX_use_certificate(state->ctx, certificate);
            X509_free(certificate);
        }
        BIO_free(certBio);

        BIO *keyBio = BIO_new_mem_buf(keyPem.data(), static_cast<int>(keyPem.size()));
        if (EVP_PKEY *key = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr))
        {
            SSL_CTX_use_PrivateKey(state->ctx, key);
            EVP_PKEY_free(key);
        }
        BIO_free(keyBio);

        state->ssl = SSL_new(state->ctx);
        if (state->ssl != nullptr)
        {
            SSL_set_fd(state->ssl, nativeFd(connectedSocket));
            state->ok = (SSL_accept(state->ssl) == 1);
        }
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
