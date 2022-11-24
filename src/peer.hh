#pragma once

#include <openssl/bio.h>
#include <openssl/ossl_typ.h>
#include <sys/socket.h>
#include <uv/unix.h>

#include <array>
#include <string>
#include <tuple>

#include "openssl/err.h"
#include "openssl/ssl.h"
#include "uv.h"

using secure_state = std::tuple<SSL*, BIO*, BIO*, std::array<char, 5000>>;
using peer_id = std::tuple<sockaddr_storage, uv_udp_t*, uv_udp_send_t, secure_state>;
using peer_representation = std::tuple<std::string, uint16_t>;

bool operator==(const peer_id& lhs, const peer_id& rhs);

peer_representation to_representation(const sockaddr* address);
peer_representation to_representation(const peer_id& peer);

peer_id create_peer(const sockaddr* address, uv_udp_t* handle, SSL_CTX* secure_context);
secure_state create_secure_state(SSL_CTX* context);

void process(peer_id& peer, uv_buf_t data);
void send(peer_id& peer, uv_buf_t* buffer);

SSL_CTX* initialize_secure_context(const std::string& certificate, const std::string& key, const std::string ca);
void initialize_openssl();
