#include <gtest/gtest.h>

#include "vigine/crypto/tls.h"

// The round-trip test wires two endpoints over a POSIX socketpair. The
// Windows equivalent (a localhost TCP pair) is a separate seat-owner task.
#if !defined(_WIN32)

#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using vigine::crypto::generateSelfSignedCert;
using vigine::crypto::SelfSignedCert;
using vigine::crypto::TlsStream;

namespace
{
std::vector<std::byte> bytesOf(std::string_view text)
{
    std::vector<std::byte> out;
    for (char character : text)
        out.push_back(static_cast<std::byte>(character));
    return out;
}
}

TEST(Tls, ClientServerRoundTripWithSelfSignedCert)
{
    const SelfSignedCert cert = generateSelfSignedCert("localhost");
    ASSERT_FALSE(cert.certPem.empty());
    ASSERT_FALSE(cert.keyPem.empty());

    int fds[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    bool                   serverOk = false;
    std::vector<std::byte> serverReceived;
    std::thread            server([&] {
        TlsStream stream = TlsStream::acceptServer(static_cast<std::uintptr_t>(fds[0]), cert.certPem,
                                                   cert.keyPem);
        serverOk = stream.ok();
        if (serverOk)
        {
            std::array<std::byte, 5> buffer{};
            if (stream.readExact(buffer))
                serverReceived.assign(buffer.begin(), buffer.end());
            (void)stream.writeAll(bytesOf("pong"));
        }
    });

    TlsStream client =
        TlsStream::connectClient(static_cast<std::uintptr_t>(fds[1]), "localhost", cert.certPem);
    EXPECT_TRUE(client.ok());
    if (client.ok())
    {
        EXPECT_TRUE(client.writeAll(bytesOf("hello")));
        std::array<std::byte, 4> reply{};
        EXPECT_TRUE(client.readExact(reply));
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(reply.data()), reply.size()), "pong");
    }

    server.join();
    EXPECT_TRUE(serverOk);
    EXPECT_EQ(serverReceived, bytesOf("hello"));

    ::close(fds[0]);
    ::close(fds[1]);
}

TEST(Tls, ClientRejectsWrongHostname)
{
    const SelfSignedCert cert = generateSelfSignedCert("localhost");
    ASSERT_FALSE(cert.certPem.empty());

    int fds[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    std::thread server([&] {
        TlsStream stream =
            TlsStream::acceptServer(static_cast<std::uintptr_t>(fds[0]), cert.certPem, cert.keyPem);
        (void)stream.ok(); // the client aborts on hostname mismatch
    });

    // The cert's SAN is "localhost"; a different expected hostname must fail
    // verification rather than silently accept the chain-valid certificate.
    TlsStream client =
        TlsStream::connectClient(static_cast<std::uintptr_t>(fds[1]), "wrong.example", cert.certPem);
    EXPECT_FALSE(client.ok());

    ::close(fds[1]); // EOF so the server's SSL_accept unblocks
    server.join();
    ::close(fds[0]);
}

TEST(Tls, ClientRejectsEmptyHostname)
{
    const SelfSignedCert cert = generateSelfSignedCert("localhost");
    ASSERT_FALSE(cert.certPem.empty());

    int fds[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    // An empty expected hostname is refused client-side before any handshake,
    // so no server is needed (starting one would just block on a peer that
    // never connects).
    TlsStream client =
        TlsStream::connectClient(static_cast<std::uintptr_t>(fds[1]), "", cert.certPem);
    EXPECT_FALSE(client.ok());

    ::close(fds[0]);
    ::close(fds[1]);
}

#endif
