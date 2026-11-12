#include "vigine/crypto/tls.h"

#include <vigine/unittest/unittest.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

// The round-trip test wires two endpoints over a POSIX socketpair. The
// Windows equivalent (a localhost TCP pair) is a separate seat-owner task.
#if !defined(_WIN32)

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using vigine::crypto::generateSelfSignedCert;
using vigine::crypto::SelfSignedCert;
using vigine::crypto::acceptTlsServer;
using vigine::crypto::connectTlsClient;
using vigine::crypto::tlsSystemRootCount;

namespace
{
std::vector<std::byte> bytesOf(std::string_view text)
{
    std::vector<std::byte> out;
    for (char character : text)
        out.push_back(static_cast<std::byte>(character));
    return out;
}
} // namespace

VIGINE_TEST(Tls, ClientServerRoundTripWithSelfSignedCert)
{
    const SelfSignedCert cert = generateSelfSignedCert("localhost");
    VIGINE_ASSERT_FALSE(cert.certPem().empty());
    VIGINE_ASSERT_FALSE(cert.keyPem().empty());

    int fds[2] = {-1, -1};
    VIGINE_ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    bool serverOk = false;
    std::vector<std::byte> serverReceived;
    std::thread server([&] {
        const auto stream = acceptTlsServer(static_cast<std::uintptr_t>(fds[0]), cert.certPem(), cert.keyPem());
        serverOk = stream->ok();
        if (serverOk)
        {
            std::array<std::byte, 5> buffer{};
            if (stream->readExact(buffer))
                serverReceived.assign(buffer.begin(), buffer.end());
            (void)stream->writeAll(bytesOf("pong"));
        }
    });

    const auto client = connectTlsClient(static_cast<std::uintptr_t>(fds[1]), "localhost", cert.certPem());
    VIGINE_EXPECT_TRUE(client->ok());
    if (client->ok())
    {
        VIGINE_EXPECT_TRUE(client->writeAll(bytesOf("hello")));
        std::array<std::byte, 4> reply{};
        VIGINE_EXPECT_TRUE(client->readExact(reply));
        VIGINE_EXPECT_EQ(std::string(reinterpret_cast<const char *>(reply.data()), reply.size()), "pong");
    }

    server.join();
    VIGINE_EXPECT_TRUE(serverOk);
    VIGINE_EXPECT_EQ(serverReceived, bytesOf("hello"));

    ::close(fds[0]);
    ::close(fds[1]);
}

VIGINE_TEST(Tls, ClientRejectsWrongHostname)
{
    const SelfSignedCert cert = generateSelfSignedCert("localhost");
    VIGINE_ASSERT_FALSE(cert.certPem().empty());

    int fds[2] = {-1, -1};
    VIGINE_ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    std::thread server([&] {
        const auto stream = acceptTlsServer(static_cast<std::uintptr_t>(fds[0]), cert.certPem(), cert.keyPem());
        (void)stream->ok(); // the client aborts on hostname mismatch
    });

    // The cert's SAN is "localhost"; a different expected hostname must fail
    // verification rather than silently accept the chain-valid certificate.
    const auto client = connectTlsClient(static_cast<std::uintptr_t>(fds[1]),
                                                "wrong.example", cert.certPem());
    VIGINE_EXPECT_FALSE(client->ok());

    ::close(fds[1]); // EOF so the server's SSL_accept unblocks
    server.join();
    ::close(fds[0]);
}

VIGINE_TEST(Tls, ClientRejectsEmptyHostname)
{
    const SelfSignedCert cert = generateSelfSignedCert("localhost");
    VIGINE_ASSERT_FALSE(cert.certPem().empty());

    int fds[2] = {-1, -1};
    VIGINE_ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    // An empty expected hostname is refused client-side before any handshake,
    // so no server is needed (starting one would just block on a peer that
    // never connects).
    const auto client = connectTlsClient(static_cast<std::uintptr_t>(fds[1]), "", cert.certPem());
    VIGINE_EXPECT_FALSE(client->ok());

    ::close(fds[0]);
    ::close(fds[1]);
}

namespace
{
struct Issued
{
    std::string certPem;
    std::string keyPem;
};

std::string pemOfCert(X509 *certificate)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, certificate);
    char *data      = nullptr;
    const long size = BIO_get_mem_data(bio, &data);
    std::string text(data, static_cast<std::size_t>(size));
    BIO_free(bio);
    return text;
}

std::string pemOfKey(EVP_PKEY *key)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
    char *data      = nullptr;
    const long size = BIO_get_mem_data(bio, &data);
    std::string text(data, static_cast<std::size_t>(size));
    BIO_free(bio);
    return text;
}

// Makes a certificate for `name`, signed by `issuer` (self-signed when issuer is null).
X509 *makeCert(EVP_PKEY *key, const char *name, X509 *issuer, EVP_PKEY *issuerKey, bool authority)
{
    X509 *certificate = X509_new();
    X509_set_version(certificate, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(certificate), authority ? 1 : 2);
    X509_gmtime_adj(X509_getm_notBefore(certificate), 0);
    X509_gmtime_adj(X509_getm_notAfter(certificate), 60L * 60 * 24);
    X509_set_pubkey(certificate, key);
    X509_NAME *subject = X509_get_subject_name(certificate);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(name), -1, -1, 0);
    X509_set_issuer_name(certificate, issuer != nullptr ? X509_get_subject_name(issuer) : subject);

    X509V3_CTX context;
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, issuer != nullptr ? issuer : certificate, certificate, nullptr, nullptr,
                   0);
    const char *constraints = authority ? "critical,CA:TRUE" : "CA:FALSE";
    X509_EXTENSION *basic   = X509V3_EXT_conf_nid(nullptr, &context, NID_basic_constraints, constraints);
    X509_add_ext(certificate, basic, -1);
    X509_EXTENSION_free(basic);
    if (!authority)
    {
        const std::string san = std::string("DNS:") + name;
        X509_EXTENSION *alt =
            X509V3_EXT_conf_nid(nullptr, &context, NID_subject_alt_name, san.c_str());
        X509_add_ext(certificate, alt, -1);
        X509_EXTENSION_free(alt);
    }
    X509_sign(certificate, issuerKey != nullptr ? issuerKey : key, nullptr);
    return certificate;
}

EVP_PKEY *newKey()
{
    return EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
}

// A test root and a "localhost" leaf signed by it.
void issueChain(Issued &root, Issued &leaf)
{
    EVP_PKEY *rootKey  = newKey();
    X509 *rootCert     = makeCert(rootKey, "Vigine Test Root", nullptr, nullptr, true);
    EVP_PKEY *leafKey  = newKey();
    X509 *leafCert     = makeCert(leafKey, "localhost", rootCert, rootKey, false);
    root.certPem       = pemOfCert(rootCert);
    leaf.certPem       = pemOfCert(leafCert);
    leaf.keyPem        = pemOfKey(leafKey);
    X509_free(rootCert);
    X509_free(leafCert);
    EVP_PKEY_free(rootKey);
    EVP_PKEY_free(leafKey);
}

// One handshake against a local server holding `leaf`; the client trusts `rootsFile` (or the
// system roots when it is empty). Returns the client's stream state through the out-params.
void handshake(const Issued &leaf, const std::string &rootsFile, bool &ok, std::string &reason)
{
    // A refused client closes early; the server's alert would then raise SIGPIPE.
    std::signal(SIGPIPE, SIG_IGN);
    int fds[2] = {-1, -1};
    VIGINE_ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    std::thread server([&] {
        const auto stream = acceptTlsServer(static_cast<std::uintptr_t>(fds[0]), leaf.certPem, leaf.keyPem);
        (void)stream->ok();
    });
    const auto client = connectTlsClient(static_cast<std::uintptr_t>(fds[1]), "localhost",
                                                {}, rootsFile);
    ok               = client->ok();
    reason           = client->failureReason();
    ::close(fds[1]);
    server.join();
    ::close(fds[0]);
}
} // namespace

VIGINE_TEST(Tls, ClientTrustsALeafOnlyThroughTheGivenRoot)
{
    Issued root;
    Issued leaf;
    issueChain(root, leaf);
    const std::string rootFile = (std::filesystem::temp_directory_path() / "vigine-test-root.pem").string();
    {
        std::ofstream out(rootFile);
        out << root.certPem;
    }

    bool ok = false;
    std::string reason;
    handshake(leaf, rootFile, ok, reason);
    VIGINE_EXPECT_TRUE(ok) << reason;

    // The system roots do not know the test root: the same server must now be refused,
    // with the verify reason.
    handshake(leaf, {}, ok, reason);
    VIGINE_EXPECT_FALSE(ok);
    VIGINE_EXPECT_NE(reason.find("certificate verification failed"), std::string::npos) << reason;
    std::remove(rootFile.c_str());
}

VIGINE_TEST(Tls, MissingRootsFileFailsWithThatReason)
{
    Issued root;
    Issued leaf;
    issueChain(root, leaf);
    bool ok = true;
    std::string reason;
    handshake(leaf, "/nonexistent/vigine-roots.pem", ok, reason);
    VIGINE_EXPECT_FALSE(ok);
    VIGINE_EXPECT_NE(reason.find("trusted roots file"), std::string::npos) << reason;
}

VIGINE_TEST(Tls, SystemRootsLoadAtLeastOne)
{
    VIGINE_EXPECT_GT(tlsSystemRootCount(), 0U);
}

#endif
