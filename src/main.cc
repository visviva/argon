
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <algorithm>
#include <cstring>
#include <list>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include "bufferpool.hh"
#include "openssl/ssl.h"
#include "peer.hh"
#include "spdlog/spdlog.h"
#include "uv.h"

using namespace spdlog;

using listener = std::tuple<uv_udp_t, BufferPool<8192, 200>, std::list<peer_id>, SSL_CTX*>;

static void on_read(uv_udp_t* req, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned /*flags*/)
{
    if (nread == 0)
    {
        return;  // skip
    }

    auto* self = reinterpret_cast<listener*>(req->data);

    if (self == nullptr)
    {
        return;
    }

    auto peer = create_peer(addr, req, std::get<3>(*self));

    if (nread < 0)
    {
        error("Read error {}\n", uv_err_name(static_cast<int>(nread)));
        uv_close(reinterpret_cast<uv_handle_t*>(req), nullptr);
        std::get<2>(*self).remove(peer);
        return;
    }

    if (nread > 0)
    {
        auto peer_repr = to_representation(peer);
        auto& peers = std::get<2>(*self);
        auto found = std::find(peers.begin(), peers.end(), peer) != peers.end();

        if (found)
        {
            info("Recv from known peer {}:{}", std::get<0>(peer_repr), std::get<1>(peer_repr));
        }
        else
        {
            peers.push_back(std::move(peer));
            info("Recv from unknown peer {}:{}", std::get<0>(peer_repr), std::get<1>(peer_repr));
        }

        auto selected = std::find(peers.begin(), peers.end(), peer);
        process(*selected, uv_buf_init(buf->base, nread));
    }
}

static void alloc_buffer(uv_handle_t* handle, size_t /*suggested_size*/, uv_buf_t* buf)
{
    auto* self = reinterpret_cast<listener*>(handle->data);
    if (self == nullptr)
    {
        return;
    }

    buf->base = std::get<1>(*self).next();
    buf->len = std::get<1>(*self).get_buffer_size();
}

std::unique_ptr<listener> open_listener(
    uv_loop_t* loop, uint16_t port, const std::string& certificate, const std::string& key, const std::string& ca)
{
    auto new_listener =
        std::make_unique<listener>(listener({}, {}, {}, initialize_secure_context(certificate, key, ca)));

    sockaddr_in recv_addr{};
    uv_ip4_addr("0.0.0.0", port, &recv_addr);

    auto& handle = std::get<0>(*new_listener);

    uv_udp_init(loop, &handle);

    uv_udp_bind(&handle, reinterpret_cast<const sockaddr*>(&recv_addr), UV_UDP_REUSEADDR);
    uv_udp_recv_start(&handle, alloc_buffer, on_read);
    handle.data = reinterpret_cast<void*>(new_listener.get());

    return new_listener;
}

int main()
{
    initialize_openssl();
    uv_loop_t* loop = uv_default_loop();

    const auto port = 8888;

    auto socket = open_listener(loop, port, "../keys/server-cert.pem", "../keys/server-key.pem", "../keys/ca-cert.pem");

    info("Secure server listening on: UDP port: {}\n", port);
    return uv_run(loop, UV_RUN_DEFAULT);
}