#include "peer.hh"

#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <uv.h>

#include <cstdint>
#include <cstring>

#include "spdlog/spdlog.h"

using namespace spdlog;

void hexdump(void* ptr, int buflen)
{
    unsigned char* buf = (unsigned char*)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16)
    {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        printf(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        printf("\n");
    }
}

peer_representation to_representation(const sockaddr* address)
{
    std::array<char, INET6_ADDRSTRLEN> string_buffer{};
    uint16_t port = 0;

    switch (address->sa_family)
    {
        case AF_INET: {
            const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
            uv_ip4_name(ipv4, string_buffer.data(), string_buffer.size());
            port = ipv4->sin_port;
        }
        break;

        case AF_INET6: {
            const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
            uv_ip6_name(ipv6, string_buffer.data(), string_buffer.size());
            port = ipv6->sin6_port;
        }
        break;
    }

    return {string_buffer.data(), port};
}

peer_representation to_representation(const peer_id& peer)
{
    return to_representation(reinterpret_cast<const sockaddr*>(&std::get<0>(peer)));
}

peer_id create_peer(const sockaddr* address, uv_udp_t* handle, SSL_CTX* secure_context)
{
    sockaddr_storage storage{};

    switch (address->sa_family)
    {
        case AF_INET: {
            const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
            memcpy(&storage, ipv4, sizeof(sockaddr_in));
        }
        break;

        case AF_INET6: {
            const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
            memcpy(&storage, ipv6, sizeof(sockaddr_in6));
        }
        break;
    }
    return {storage, handle, {}, create_secure_state(secure_context)};
}

bool operator==(const peer_id& lhs, const peer_id& rhs)
{
    auto lhs_repr = to_representation(lhs);
    auto rhs_repr = to_representation(rhs);
    return lhs_repr == rhs_repr;
}

void send(peer_id& peer, uv_buf_t buffer)
{
    info("Sending {} bytes", buffer.len);
    uv_udp_send(&std::get<2>(peer),
                std::get<1>(peer),
                &buffer,
                1,
                reinterpret_cast<const sockaddr*>(&std::get<0>(peer)),
                [](uv_udp_send_t* /*req*/, int status) -> void {
                    if (status != 0)
                    {
                        error("uv_udp_send_cb error: {}\n", uv_strerror(status));
                    }
                });
}

SSL* get_ssl(const secure_state& state)
{
    return std::get<0>(state);
}

BIO* get_rbio(const secure_state& state)
{
    return std::get<1>(state);
}

BIO* get_wbio(const secure_state& state)
{
    return std::get<2>(state);
}

char* get_buffer(secure_state& state)
{
    return std::get<3>(state).data();
}

void print_ssl_state(const secure_state& state)
{
    const auto* text = SSL_state_string_long(std::get<0>(state));
    info("SSL state: {}", text);
}

void print_error(const secure_state& state, int error_num)
{
    auto err = SSL_get_error(get_ssl(state), error_num);

    if (err == SSL_ERROR_SSL)
    {
        error("{}", ERR_error_string(ERR_get_error(), nullptr));
    }

    error("{}", SSL_state_string(get_ssl(state)));
}

void process(peer_id& peer, uv_buf_t data)
{
    auto& ssl = std::get<3>(peer);
    char* buffer = get_buffer(ssl);

    BIO_write(get_rbio(ssl), data.base, static_cast<int>(data.len));

    if (!SSL_is_init_finished(get_ssl(ssl)))
    {
        info("Processing {} bytes of handshake data", data.len);
        print_ssl_state(ssl);
        auto ret = SSL_do_handshake(get_ssl(ssl));
        if (ret <= 0)
        {
            print_error(ssl, ret);
            print_ssl_state(ssl);
        }
        print_ssl_state(ssl);

        auto len = BIO_pending(get_wbio(ssl));
        if (len > 0)
        {
            auto nread = BIO_read(get_wbio(ssl), buffer, len);
            auto buf = uv_buf_init(buffer, nread);
            send(peer, buf);
        }
        return;
    }

    // decrypt, print to stdout, encrypt and send back
    auto nread = SSL_read(get_ssl(ssl), buffer, 5000);
    std::string clear_text(get_buffer(ssl), nread);
    info("Echo: {}", clear_text);
    SSL_write(get_ssl(ssl), get_buffer(ssl), nread);
    auto len = BIO_pending(get_wbio(ssl));
    if (len > 0)
    {
        BIO_read(get_wbio(ssl), buffer, len);
        auto buf = uv_buf_init(buffer, len);
        send(peer, buf);
    }
}

secure_state create_secure_state(SSL_CTX* context)
{
    auto* ssl = SSL_new(context);
    SSL_set_accept_state(ssl);

    auto* rbio = BIO_new(BIO_s_mem());
    auto* wbio = BIO_new(BIO_s_mem());

    SSL_set_bio(ssl, rbio, wbio);

    return {ssl, rbio, wbio, {}};
}

SSL_CTX* initialize_secure_context(const std::string& certificate, const std::string& key, const std::string ca)
{
    auto* secure_context = SSL_CTX_new(DTLS_method());
    SSL_CTX_use_certificate_file(secure_context, certificate.c_str(), SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(secure_context, key.c_str(), SSL_FILETYPE_PEM);
    SSL_CTX_load_verify_locations(secure_context, ca.c_str(), nullptr);
    SSL_CTX_check_private_key(secure_context);
    SSL_CTX_set_verify(secure_context,
                       SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       [](int preverify, X509_STORE_CTX* /*cert*/) -> int { return preverify; });
    SSL_CTX_set_cipher_list(secure_context, "DEFAULT:eNULL@SECLEVEL=0");
    return secure_context;
}

void initialize_openssl()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_SSL_strings();
}