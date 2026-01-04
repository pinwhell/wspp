#pragma once

#include <iostream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <array>
#include <random>
#include <chrono>
#include <functional>
#include <thread>
#include <algorithm>
#include <cctype>
#include <mutex>
#include <span>
#include <optional>

#ifndef WSPP_UNUSED
#define WSPP_UNUSED(x) (void)(x)
#endif

#ifdef WSPP_USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#ifdef _MSC_VER
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ws2_32.lib")
#endif
#else
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

namespace wspp {
    namespace detail {

        using binary_view = std::span<const std::uint8_t>;


#ifdef _WIN32
        using socket_t = SOCKET;
        constexpr socket_t invalid_socket = INVALID_SOCKET;
        inline int last_error() { return WSAGetLastError(); }
        inline bool would_block(int e) { return e == WSAEWOULDBLOCK; }
        inline void socket_close(socket_t s) { ::closesocket(s); }
        inline void set_non_blocking(socket_t s) {
            u_long mode = 1;
            ioctlsocket(s, FIONBIO, &mode);
        }

#ifdef WSPP_USE_OPENSSL
        static void load_windows_root_certs(SSL_CTX* ctx) {
            HCERTSTORE hStore = CertOpenSystemStoreA(0, "ROOT");
            if (!hStore) return;

            X509_STORE* store = SSL_CTX_get_cert_store(ctx);
            PCCERT_CONTEXT pCtx = nullptr;

            while ((pCtx = CertEnumCertificatesInStore(hStore, pCtx)) != nullptr) {
                const unsigned char* p = pCtx->pbCertEncoded;
                X509* x = d2i_X509(nullptr, &p, pCtx->cbCertEncoded);
                if (x) {
                    X509_STORE_add_cert(store, x);
                    X509_free(x);
                }
            }

            CertCloseStore(hStore, 0);
        }
#endif
#else
        using socket_t = int;
        constexpr socket_t invalid_socket = -1;
        inline int last_error() { return errno; }
        inline bool would_block(int e) { return e == EWOULDBLOCK || e == EAGAIN; }
        inline void socket_close(socket_t s) { ::close(s); }
        inline void set_non_blocking(socket_t s) {
            int flags = fcntl(s, F_GETFL, 0);
            fcntl(s, F_SETFL, flags | O_NONBLOCK);
        }
#endif

        // Should come with policy in the future
        constexpr size_t MAX_FRAME_SIZE = 32 * 1024; // 32 KB
        constexpr size_t MAX_MESSAGE_SIZE = 9 * 1024 * 1024; // 9 MB

        enum class io_result : int {
            fatal = -1,
            no_data = 0,
            ok = 1
        };

        enum class ws_connection_state {
            handshake,
            open,
            closing,
            closed
        };

        enum class ws_opcode : uint8_t {
            continuation = 0x0,
            text = 0x1,
            binary = 0x2,
            close = 0x8,
            ping = 0x9,
            pong = 0xA
        };

        enum class frame_result {
            need_more,
            frame_ready,
            protocol_error,
            too_big
        };

        enum class reactor_event {
            readable,
            writable,
            error
        };

        enum class ws_close_code : uint16_t {
            normal = 1000,
            going_away = 1001,
            protocol_error = 1002,
            unsupported_data = 1003,
            invalid_payload = 1007,
            message_too_big = 1009
        };

        enum class tcp_state {
            connecting,
            connected,
            closed
        };

        enum class ws_step {
            idle,        // no progress
            message,     // message ready (message + message_opcode)
            closed,      // clean close
            error        // protocol or IO error
        };

        enum class wspp_event {
            idle,
            message,
            closed,
            error
        };

        struct ws_client_role {};
        struct ws_server_role {};

        template <typename Role>
        struct ws_mask_policy;

        template <>
        struct ws_mask_policy<ws_client_role> {
            static constexpr bool must_mask = true;
        };

        template <>
        struct ws_mask_policy<ws_server_role> {
            static constexpr bool must_mask = false;
        };

        template <typename Role>
        struct ws_inbound_policy;

        template <>
        struct ws_inbound_policy<ws_client_role> {
            static constexpr bool expect_mask = false; // server → client
        };

        template <>
        struct ws_inbound_policy<ws_server_role> {
            static constexpr bool expect_mask = true;  // client → server
        };

#ifdef WSPP_USE_OPENSSL
        struct openssl_client_policy {
            static SSL_CTX* create_ctx() {
                SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
                SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
                SSL_CTX_set_default_verify_paths(ctx);
#ifdef _WIN32
                load_windows_root_certs(ctx);
#endif
                return ctx;
            }
        };
#endif

        struct io_read {
            io_result result;
            int bytes;
        };

        struct tcp_socket {
            socket_t sock = invalid_socket;
            bool open = false;

            tcp_socket() = default;

            explicit tcp_socket(socket_t s)
                : sock(s), open(s != invalid_socket) {
            }

            ~tcp_socket() { close(); }

            tcp_socket(const tcp_socket&) = delete;
            tcp_socket& operator=(const tcp_socket&) = delete;

            tcp_socket(tcp_socket&& o) noexcept {
                sock = o.sock;
                open = o.open;
                o.sock = invalid_socket;
                o.open = false;
            }

            tcp_socket& operator=(tcp_socket&& o) noexcept {
                if (this != &o) {
                    close();
                    sock = o.sock;
                    open = o.open;
                    o.sock = invalid_socket;
                    o.open = false;
                }
                return *this;
            }

            io_read read(void* data, int capacity) {
                int n = (int)::recv(sock, (char*)data, capacity, 0);
                if (n < 0) {
                    if (would_block(last_error()))
                        return { io_result::no_data, 0 };
                    return { io_result::fatal, 0 };
                }
                if (n == 0)
                    return { io_result::fatal, 0 };
                return { io_result::ok, n };
            }

            int write(const void* data, int size) {
                return (int)::send(sock, (const char*)data, size, 0);
            }

            void on_writable() {
                // no-op: already connected
            }

            bool wants_write() const {
                return false;
            }

            bool is_open() const {
                return open;
            }

            bool is_alive() const {
                return open;
            }

            socket_t handle() const {
                return sock;
            }

            void close() {
                if (sock != invalid_socket) {
                    socket_close(sock);
                    sock = invalid_socket;
                }
                open = false;
            }
        };

        struct tcp_connector {
            using transport_t = tcp_socket;
            tcp_connector() = default;
            std::optional<transport_t> connect(const char* host, const char* port) {
                addrinfo hints{};
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_protocol = IPPROTO_TCP;

                addrinfo* res = nullptr;
                if (::getaddrinfo(host, port, &hints, &res) != 0)
                    return {};

                transport_t sock{ ::socket(res->ai_family, res->ai_socktype, res->ai_protocol) };
                if (sock.handle() == invalid_socket) {
                    ::freeaddrinfo(res);
                    return {};
                }

                // BLOCKING CONNECT: TODO NON-BLOCKING
                int r = ::connect(sock.handle(), res->ai_addr, (int)res->ai_addrlen);

                set_non_blocking(sock.handle());
                ::freeaddrinfo(res);

                if (r != 0 && !would_block(last_error())) {
                    return {};
                }

                return sock;
            }
        };

        struct tcp_acceptor {
            socket_t listen_fd = invalid_socket;
            bool open = false;

            tcp_acceptor() = default;
            ~tcp_acceptor() { close(); }

            bool bind_and_listen(uint16_t port) {
                listen_fd = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
                if (listen_fd == invalid_socket)
                    return false;

                int no = 0;
                setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY,
                    (const char*)&no, sizeof(no));

                sockaddr_in6 addr{};
                addr.sin6_family = AF_INET6;
                addr.sin6_addr = in6addr_any;
                addr.sin6_port = htons(port);

                if (::bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) != 0)
                    return false;

                if (::listen(listen_fd, SOMAXCONN) != 0)
                    return false;

                set_non_blocking(listen_fd);
                open = true;
                return true;
            }

            std::optional<tcp_socket> try_accept() {
                if (!open) return {};

                sockaddr_storage ss{};
                socklen_t len = sizeof(ss);

                socket_t c = ::accept(listen_fd, (sockaddr*)&ss, &len);
                if (c == invalid_socket) {
                    if (would_block(last_error()))
                        return {};
                    return {}; // hard error → ignore or close listener
                }

                set_non_blocking(c);
                return tcp_socket{ c };
            }

            socket_t handle() const { return listen_fd; }
            bool is_open() const { return open; }

            void close() {
                if (listen_fd != invalid_socket) {
                    socket_close(listen_fd);
                    listen_fd = invalid_socket;
                }
                open = false;
            }
        };

#ifdef WSPP_USE_OPENSSL
        struct tls_socket {
            SSL_CTX* ctx = nullptr;
            SSL* ssl = nullptr;
            BIO* bio = nullptr;
            socket_t sock = invalid_socket;
            bool     open = false;

            tls_socket() = default;
            ~tls_socket() { reset(); }

            tls_socket(const tls_socket&) = delete;
            tls_socket& operator=(const tls_socket&) = delete;

            tls_socket(tls_socket&& o) noexcept { *this = std::move(o); }

            tls_socket& operator=(tls_socket&& o) noexcept {
                if (this != &o) {
                    reset();
                    ctx = o.ctx;
                    ssl = o.ssl;
                    bio = o.bio;
                    sock = o.sock;
                    open = o.open;

                    o.ctx = nullptr;
                    o.ssl = nullptr;
                    o.bio = nullptr;
                    o.sock = invalid_socket;
                    o.open = false;
                }
                return *this;
            }

            io_read read(void* data, int capacity) {
                if (!open) return { io_result::fatal, 0 };

                int ret = BIO_read(bio, data, capacity);

                if (ret > 0)
                    return { io_result::ok, ret };

                if (ret == 0)
                    return { io_result::fatal, 0 }; // clean shutdown

                // ret < 0 → check SSL state
                int err = SSL_get_error(ssl, ret);

                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    return { io_result::no_data, 0 };

                return { io_result::fatal, 0 };
            }

            int write(const void* data, int size) {
                if (!open) return -1;

                int r = BIO_write(bio, data, size);
                if (r > 0)
                    return r;

                if (BIO_should_retry(bio))
                    return 0;

                return -1;
            }

            void on_writable() {
                // no-op: already connected
            }

            bool wants_write() const {
                return false;
            }

            void reset() {
                if (bio) {
                    BIO_free_all(bio);
                    bio = nullptr;
                }
                if (ctx) {
                    SSL_CTX_free(ctx);
                    ctx = nullptr;
                }
                ssl = nullptr;
                sock = invalid_socket;
                open = false;
            }

            void close() { reset(); }

            bool is_open()  const { return open; }
            bool is_alive() const { return open; }
            socket_t handle() const { return sock; }
        };

        template<class Policy>
        struct tls_connector {
            std::optional<tls_socket> connect(const char* host, const char* port) {
                tls_socket sock{};
                sock.ctx = Policy::create_ctx();
                if (!sock.ctx) return {};

                sock.bio = BIO_new_ssl_connect(sock.ctx);
                if (!sock.bio) return {};

                BIO_get_ssl(sock.bio, &sock.ssl);
                if (!sock.ssl) return {};

                SSL_set_tlsext_host_name(sock.ssl, host);

                std::string target = std::string(host) + ":" + port;
                BIO_set_conn_hostname(sock.bio, target.c_str());

                // ---- BLOCKING CONNECT + HANDSHAKE ----
                // TODO NON-BLOCKING
                BIO_set_nbio(sock.bio, 0);

                if (BIO_do_connect(sock.bio) <= 0)
                    return {};

                if (BIO_do_handshake(sock.bio) <= 0)
                    return {};

                // Extract underlying socket
                int fd = -1;
                BIO_get_fd(sock.bio, &fd);
                sock.sock = (socket_t)fd;

                set_non_blocking(sock.sock);
                BIO_set_nbio(sock.bio, 1);

                sock.open = true;
                return sock;
            }
        };
#endif

        template<class Transport>
        struct byte_stream {
            Transport& t;
            std::vector<char> out = {};

            socket_t handle() const { return t.handle(); }
            bool is_open() const { return t.is_open(); }

            bool wants_write() const {
                return !out.empty() || t.wants_write();
            }

            void on_writable() {
                t.on_writable();   // TCP connect o TLS handshake
                flush();
            }

            io_read read(void* b, int n) {
                return t.read(b, n);
            }

            int write(const void* b, int n) {
                out.insert(out.end(), (char*)b, (char*)b + n);
                return n;
            }

            void flush() {
                if (out.empty()) return;
                int n = t.write(out.data(), (int)out.size());
                if (n > 0)
                    out.erase(out.begin(), out.begin() + n);
            }
        };
        struct read_buffer {
            std::vector<char> buf{};

            void append(const char* data, size_t n) {
                buf.insert(buf.end(), data, data + n);
            }

            int find(const char* seq, size_t len) const {
                for (size_t i = 0; i + len <= buf.size(); ++i) {
                    if (std::memcmp(buf.data() + i, seq, len) == 0)
                        return (int)i;
                }
                return -1;
            }

            void consume(size_t n) {
                buf.erase(buf.begin(), buf.begin() + n);
            }

            const char* data() const { return buf.data(); }
            size_t size() const { return buf.size(); }
        };

        enum class ws_phase {
            frame_header,
            frame_payload,
            closed
        };

        struct utf8_validator {
            uint32_t codepoint = 0;
            uint8_t  remaining = 0;
            uint8_t expected = 0;

            bool feed(const uint8_t* data, size_t n) {
                for (size_t i = 0; i < n; ++i) {
                    if (!feed_byte(data[i]))
                        return false;
                }
                return true;
            }

            bool feed_byte(uint8_t b) {
                if (remaining == 0) {
                    if (b <= 0x7F) {
                        return true;
                    }
                    else if ((b & 0xE0) == 0xC0) {
                        if (b < 0xC2) return false; // overlong
                        codepoint = b & 0x1F;
                        remaining = 1;
                        expected = 2;
                    }
                    else if ((b & 0xF0) == 0xE0) {
                        codepoint = b & 0x0F;
                        remaining = 2;
                        expected = 3;
                    }
                    else if ((b & 0xF8) == 0xF0) {
                        if (b > 0xF4) return false; // > U+10FFFF
                        codepoint = b & 0x07;
                        remaining = 3;
                        expected = 4;
                    }
                    else {
                        return false;
                    }
                    return true;
                }

                // continuation byte
                if ((b & 0xC0) != 0x80)
                    return false;

                codepoint = (codepoint << 6) | (b & 0x3F);
                remaining--;

                if (remaining == 0) {
                    if ((expected == 2 && codepoint < 0x80) ||
                        (expected == 3 && codepoint < 0x800) ||
                        (expected == 4 && codepoint < 0x10000) ||
                        (codepoint >= 0xD800 && codepoint <= 0xDFFF) ||
                        (codepoint > 0x10FFFF))
                        return false;
                }

                return true;
            }

            bool finished() const {
                return remaining == 0;
            }

            void reset() {
                codepoint = 0;
                remaining = 0;
            }
        };

        struct ws_state {
            ws_phase phase = ws_phase::frame_header;
            ws_opcode opcode = ws_opcode::continuation;
            bool fin = false;
            bool fragmented = false;
            size_t payload_len = 0;
            uint8_t mask_key[4]{};

            ws_opcode msg_opcode = ws_opcode::continuation;    // 🔑 opcode real
            std::vector<std::uint8_t> msg_buffer;        // 🔑 acumulador
            utf8_validator utf8;
        };

        template <typename Role>
        frame_result try_parse_frame_header(read_buffer& rb, ws_state& ws) {
            if (rb.size() < 2)
                return frame_result::need_more;

            const unsigned char* p =
                (const unsigned char*)rb.data();

            if (p[0] & 0x70) { // RSV1, RSV2, RSV3
                return frame_result::protocol_error;
            }

            ws.fin = (p[0] & 0x80) != 0;
            ws.opcode = ws_opcode(p[0] & 0x0F);
            bool is_control =
                ws.opcode == ws_opcode::ping ||
                ws.opcode == ws_opcode::pong ||
                ws.opcode == ws_opcode::close;
            bool masked = (p[1] & 0x80) != 0;

            constexpr bool MUST_BE_MASKED = ws_inbound_policy<Role>::expect_mask;

            if constexpr (MUST_BE_MASKED) {
                if (!masked)
                    return frame_result::protocol_error; // RFC 1002
            }
            else {
                if (masked)
                    return frame_result::protocol_error; // RFC 1002
            }

            ws.payload_len = p[1] & 0x7F;

            size_t header_size = 2;

            if (ws.payload_len == 126) {
                if (rb.size() < 4) return frame_result::need_more;
                ws.payload_len =
                    (p[2] << 8) | p[3];
                header_size = 4;
            }
            else if (ws.payload_len == 127) {
                if (rb.size() < 10) return frame_result::need_more;
                ws.payload_len = 0;
                for (int i = 0; i < 8; ++i)
                    ws.payload_len = (ws.payload_len << 8) | p[2 + i];
                header_size = 10;
            }
            if (is_control && ws.payload_len > 125)
                return frame_result::protocol_error;

            if (ws.payload_len > MAX_FRAME_SIZE)
                return frame_result::too_big;

            if (masked) {
                if (rb.size() < header_size + 4) return frame_result::need_more;
                std::memcpy(ws.mask_key, rb.data() + header_size, 4);
                header_size += 4;
            }

            rb.consume(header_size);
            ws.phase = ws_phase::frame_payload;
            return frame_result::frame_ready;
        }

        inline frame_result try_read_frame_payload(read_buffer& rb, ws_state& ws,
            std::vector<std::uint8_t>& out_payload) {
            if ((uint64_t)rb.size() < ws.payload_len)
                return frame_result::need_more;

            if (ws.payload_len > 0) {
                out_payload.resize(ws.payload_len);
                if (rb.size() < ws.payload_len) return frame_result::need_more;
                std::memcpy(out_payload.data(), rb.data(), ws.payload_len);
            }

            // unmask if needed
            if (ws.mask_key[0] | ws.mask_key[1] | ws.mask_key[2] | ws.mask_key[3]) {
                for (size_t i = 0; i < out_payload.size(); ++i)
                    out_payload[i] ^= ws.mask_key[i % 4];
            }

            rb.consume((int)ws.payload_len);

            // reset for next frame
            ws.payload_len = 0;
            ws.mask_key[0] = ws.mask_key[1] = ws.mask_key[2] = ws.mask_key[3] = 0;
            ws.phase = ws_phase::frame_header;

            return frame_result::frame_ready;
        }

        struct mt_rng {
            std::mt19937 gen;
            std::uniform_int_distribution<uint32_t> dist;

            mt_rng()
                : gen(std::random_device{}()),
                dist(0, 0xFFFFFFFFu) {
            }

            uint32_t next_u32() {
                return dist(gen);
            }
        };

        template <typename ByteStream, typename Role>
        void ws_send_frame(ByteStream& stream,
            ws_opcode opcode,
            const void* data,
            size_t size)
        {
            constexpr bool MASK = ws_mask_policy<Role>::must_mask;

            uint8_t header[14];
            size_t header_len = 0;

            header[0] = 0x80 | (uint8_t(opcode) & 0x0F);

            if (size <= 125) {
                header[1] = (MASK ? 0x80 : 0x00) | uint8_t(size);
                header_len = 2;
            }
            else if (size <= 0xFFFF) {
                header[1] = (MASK ? 0x80 : 0x00) | 126;
                header[2] = uint8_t(size >> 8);
                header[3] = uint8_t(size);
                header_len = 4;
            }
            else {
                header[1] = (MASK ? 0x80 : 0x00) | 127;
                for (int i = 0; i < 8; ++i)
                    header[2 + i] = uint8_t(size >> (56 - i * 8));
                header_len = 10;
            }

            uint8_t mask[4]{};

            if constexpr (MASK) {
                static mt_rng rng;
                uint32_t r = rng.next_u32();
                mask[0] = uint8_t(r >> 24);
                mask[1] = uint8_t(r >> 16);
                mask[2] = uint8_t(r >> 8);
                mask[3] = uint8_t(r);

                std::memcpy(header + header_len, mask, 4);
                header_len += 4;
            }

            stream.write(header, int(header_len));

            if constexpr (MASK) {
                std::vector<uint8_t> masked(size);
                const uint8_t* p = (const uint8_t*)data;
                for (size_t i = 0; i < size; ++i)
                    masked[i] = p[i] ^ mask[i % 4];

                stream.write(masked.data(), int(masked.size()));
            }
            else {
                stream.write(data, int(size));
            }
        }

        inline std::string base64_encode(const uint8_t* data, size_t len) {
            static const char table[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

            std::string out;
            out.reserve(((len + 2) / 3) * 4);

            for (size_t i = 0; i < len; i += 3) {
                uint32_t v = 0;
                int n = 0;

                for (int j = 0; j < 3; ++j) {
                    v <<= 8;
                    if (i + j < len) {
                        v |= data[i + j];
                        ++n;
                    }
                }

                for (int j = 0; j < 4; ++j) {
                    if (j <= n) {
                        out.push_back(table[(v >> (18 - 6 * j)) & 0x3F]);
                    }
                    else {
                        out.push_back('=');
                    }
                }
            }

            return out;
        }

        inline int base64_value(char c) {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
        }

        inline bool base64_decode(std::string_view in, std::vector<uint8_t>& out) {
            if (in.size() % 4 != 0)
                return false;

            out.clear();
            out.reserve((in.size() / 4) * 3);

            for (size_t i = 0; i < in.size(); i += 4) {
                uint32_t v = 0;
                int pad = 0;
                bool padding_started = false;

                for (int j = 0; j < 4; ++j) {
                    char c = in[i + j];

                    if (c == '=') {
                        padding_started = true;
                        ++pad;
                        v <<= 6;
                    }
                    else {
                        if (padding_started)
                            return false; // non-padding after '='

                        int x = base64_value(c);
                        if (x < 0)
                            return false;

                        v = (v << 6) | x;
                    }
                }

                if (pad > 2)
                    return false;

                for (int j = 0; j < 3 - pad; ++j)
                    out.push_back(static_cast<uint8_t>((v >> (16 - j * 8)) & 0xFF));
            }

            return true;
        }

        struct sha1_ctx {
            uint32_t h[5];
            uint64_t len_bits;
            uint8_t buf[64];
            size_t buf_len;
        };

        inline uint32_t rol(uint32_t x, uint32_t n) {
            return (x << n) | (x >> (32 - n));
        }

        inline void sha1_init(sha1_ctx& ctx) {
            ctx.h[0] = 0x67452301;
            ctx.h[1] = 0xEFCDAB89;
            ctx.h[2] = 0x98BADCFE;
            ctx.h[3] = 0x10325476;
            ctx.h[4] = 0xC3D2E1F0;
            ctx.len_bits = 0;
            ctx.buf_len = 0;
        }

        inline void sha1_process_block(sha1_ctx& ctx, const uint8_t block[64]) {
            uint32_t w[80];

            for (int i = 0; i < 16; ++i) {
                w[i] =
                    (uint32_t(block[i * 4]) << 24) |
                    (uint32_t(block[i * 4 + 1]) << 16) |
                    (uint32_t(block[i * 4 + 2]) << 8) |
                    (uint32_t(block[i * 4 + 3]));
            }

            for (int i = 16; i < 80; ++i)
                w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

            uint32_t a = ctx.h[0];
            uint32_t b = ctx.h[1];
            uint32_t c = ctx.h[2];
            uint32_t d = ctx.h[3];
            uint32_t e = ctx.h[4];

            for (int i = 0; i < 80; ++i) {
                uint32_t f, k;

                if (i < 20) {
                    f = (b & c) | (~b & d);
                    k = 0x5A827999;
                }
                else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                }
                else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                }
                else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                uint32_t temp = rol(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = rol(b, 30);
                b = a;
                a = temp;
            }

            ctx.h[0] += a;
            ctx.h[1] += b;
            ctx.h[2] += c;
            ctx.h[3] += d;
            ctx.h[4] += e;
        }

        inline void sha1_update(sha1_ctx& ctx, const uint8_t* data, size_t len) {
            ctx.len_bits += uint64_t(len) * 8;

            while (len > 0) {
                size_t n = std::min(len, 64 - ctx.buf_len);
                std::memcpy(ctx.buf + ctx.buf_len, data, n);
                ctx.buf_len += n;
                data += n;
                len -= n;

                if (ctx.buf_len == 64) {
                    sha1_process_block(ctx, ctx.buf);
                    ctx.buf_len = 0;
                }
            }
        }

        inline void sha1_final(sha1_ctx& ctx, uint8_t out[20]) {
            ctx.buf[ctx.buf_len++] = 0x80;

            if (ctx.buf_len > 56) {
                while (ctx.buf_len < 64)
                    ctx.buf[ctx.buf_len++] = 0;
                sha1_process_block(ctx, ctx.buf);
                ctx.buf_len = 0;
            }

            while (ctx.buf_len < 56)
                ctx.buf[ctx.buf_len++] = 0;

            for (int i = 7; i >= 0; --i)
                ctx.buf[ctx.buf_len++] = (ctx.len_bits >> (i * 8)) & 0xFF;

            sha1_process_block(ctx, ctx.buf);

            for (int i = 0; i < 5; ++i) {
                out[i * 4] = (ctx.h[i] >> 24) & 0xFF;
                out[i * 4 + 1] = (ctx.h[i] >> 16) & 0xFF;
                out[i * 4 + 2] = (ctx.h[i] >> 8) & 0xFF;
                out[i * 4 + 3] = ctx.h[i] & 0xFF;
            }
        }

        inline std::array<uint8_t, 20> sha1_digest(const uint8_t* data, size_t len) {
            sha1_ctx ctx{};
            sha1_init(ctx);
            sha1_update(ctx, data, len);

            std::array<uint8_t, 20> out{};
            sha1_final(ctx, out.data());
            return out;
        }

        inline std::string generate_ws_key() {
            uint8_t bytes[16];
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<uint16_t> dist(0, 255);
            for (auto& b : bytes) b = (uint8_t)dist(gen);
            return base64_encode(bytes, 16);
        }

        struct ws_server_handshake {
            std::string key;
            bool complete = false;
        };

        inline std::string make_accept(std::string_view key) {
            static const char guid[] =
                "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

            std::string in = std::string(key) + guid;
            auto h = wspp::detail::sha1_digest(
                (const uint8_t*)in.data(), in.size());

            return wspp::detail::base64_encode(h.data(), h.size());
        }

        inline bool validate_accept(const std::string& key,
            const std::string& accept)
        {
            static const char guid[] =
                "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

            std::string input = key + guid;

            auto hash = sha1_digest(
                reinterpret_cast<const uint8_t*>(input.data()),
                input.size());

            std::string expected =
                base64_encode(hash.data(), hash.size());

            return expected == accept;
        }

        struct http_handshake {
            std::string accept;
            int consumed = 0;
        };

        static bool iequals(char a, char b) {
            return std::tolower((unsigned char)a) ==
                std::tolower((unsigned char)b);
        }

        static bool istarts_with(const char* p, const char* end,
            const char* key) {
            while (*key && p < end) {
                if (!iequals(*p++, *key++))
                    return false;
            }
            return *key == 0;
        }

        inline bool parse_http_handshake(read_buffer& rb, http_handshake& out)
        {
            const char* buf = rb.data();

            // find end of headers
            int end = rb.find("\r\n\r\n", 4);
            if (end < 0)
                return false;

            const char* p = buf;
            const char* headers_end = buf + end + 2;

            while (p < headers_end) {
                const char* c = "\r\n";
                const char* line_end = std::search(p, headers_end, c, c + 2);

                if (line_end > headers_end)
                    line_end = headers_end;

                if (istarts_with(p, line_end, "sec-websocket-accept")) {
                    const char* v = p + strlen("sec-websocket-accept");
                    while (v < line_end && (*v == ' ' || *v == ':')) ++v;
                    out.accept.assign(v, line_end);
                    out.consumed = end + 4;
                    return true;
                }

                p = line_end + 2;
            }

            return false;
        }

        inline bool parse_ws_server_handshake(
            wspp::detail::read_buffer& rb,
            ws_server_handshake& hs)
        {
            const char* buf = rb.data();

            int end = rb.find("\r\n\r\n", 4);
            if (end < 0)
                return false;

            const char* p = buf;
            const char* headers_end = buf + end + 2;

            while (p < headers_end) {
                const char* rn = "\r\n";
                const char* line_end =
                    std::search(p, headers_end, rn, rn + 2);

                if (istarts_with(p, line_end, "sec-websocket-key")) {
                    const char* v = p + strlen("sec-websocket-key");
                    while (v < line_end && (*v == ' ' || *v == ':')) ++v;
                    hs.key.assign(v, line_end);
                }

                p = line_end + 2;
            }

            if (hs.key.empty())
                return false;

            rb.consume(end + 4);
            hs.complete = true;
            return true;
        }

        struct pending_msg {
            bool is_text = false;
            std::vector<std::uint8_t> data{};
        };

        inline bool is_valid_utf8(const std::vector<char>& data) {
            utf8_validator utf8;
            return utf8.feed((const uint8_t*)data.data(), 
                data.size()) && utf8.finished();
        }

        template <typename ByteStream, typename Role>
        void ws_send_close(ByteStream& stream, ws_close_code code) {
            uint16_t be = htons(static_cast<uint16_t>(code));
            ws_send_frame<ByteStream, Role>(stream, ws_opcode::close, &be, 2);
        }

        template<typename T>
        inline bool is_valid_close_code(T code_)
        {
            std::uint16_t code = (std::uint16_t)code_;
            if (code < 1000 ||
                code == 1004 || code == 1005 || code == 1006 ||
                (code >= 1016 && code <= 2999))
                return false;
            return true;
        }

        template<typename T>
        ws_close_code normalize_close_code(T code, ws_close_code def = ws_close_code::normal)
        {
            return is_valid_close_code<T>(code) ? ws_close_code(code) : def;
        }

        inline bool handle_close_payload(const std::vector<char>& payload) {
            if (payload.empty())
                return true;

            if (payload.size() == 1)
                return false; // RFC: invalid

            uint16_t code =
                (uint8_t(payload[0]) << 8) |
                uint8_t(payload[1]);

            if (!is_valid_close_code(code)) 
                return false;

            if (payload.size() > 2) {
                std::vector<char> reason(payload.begin() + 2, payload.end());
                if (!is_valid_utf8(reason))
                    return false;
            }

            return true;
        }

        struct server_handshake {
            static constexpr bool enabled = true;
            static constexpr bool is_initiator = false;

            ws_server_handshake hs;
            std::string response;

            bool try_consume(read_buffer& rb, ws_state& ws_state, ws_connection_state& conn_state)
            {
                WSPP_UNUSED(ws_state);

                if (!parse_ws_server_handshake(rb, hs))
                    return false;

                response =
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Accept: " +
                    make_accept(hs.key) + "\r\n"
                    "\r\n";

                conn_state = ws_connection_state::open;
                return true;
            }
        };

        struct client_handshake {
            static constexpr bool enabled = true;
            static constexpr bool is_initiator = true;

            std::string key;
            bool request_sent = false;
            std::string path;
            std::string host;

            std::string build_request()
            {
                key = generate_ws_key();

                return
                    "GET " + std::string(path) + " HTTP/1.1\r\n"
                    "Host: " + std::string(host) + "\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Key: " + key + "\r\n"
                    "Sec-WebSocket-Version: 13\r\n"
                    "\r\n";
            }

            bool try_consume(read_buffer& rb,
                ws_state&,
                ws_connection_state& state)
            {
                http_handshake hs;
                if (!parse_http_handshake(rb, hs))
                    return false;

                if (!validate_accept(key, hs.accept)) {
                    state = ws_connection_state::closed;
                    return true;
                }

                rb.consume(hs.consumed);
                state = ws_connection_state::open;
                return true;
            }
        };

        template<
            typename Transport, 
            typename Role, 
            typename HandshakePolicy>
        struct ws_endpoint {
            using byte_stream_t = byte_stream<Transport>;
            Transport transport;
            byte_stream_t stream{ transport };
            read_buffer rb;
            ws_state ws;
            ws_connection_state state = ws_connection_state::handshake;
            std::vector<pending_msg> outbox;
            std::vector<std::uint8_t> message;
            ws_opcode message_opcode = ws_opcode::continuation;
            ws_close_code close_code = ws_close_code::normal;
            HandshakePolicy handshake;
            //std::chrono::steady_clock::time_point last_rx;
            //std::chrono::steady_clock::time_point last_ping;
            //std::chrono::steady_clock::time_point close_sent_at;
            //bool close_reported = false;
            //std::string ws_key;

            ws_endpoint() = default;
            ws_endpoint(const ws_endpoint&) = delete;
            ws_endpoint& operator=(const ws_endpoint&) = delete;
            ws_endpoint(ws_endpoint&& o) noexcept 
            {
                *this = std::move(o);
            }
            ws_endpoint& operator=(ws_endpoint&& o) noexcept {
                if (this != &o) {
                    transport = std::move(o.transport);
                    stream = byte_stream_t{ transport };

                    rb = std::move(o.rb);
                    ws = std::move(o.ws);
                    outbox = std::move(o.outbox);
                    message = std::move(o.message);
                    handshake = std::move(o.handshake);

                    state = o.state;
                    message_opcode = o.message_opcode;
                    close_code = o.close_code;

                    o.stream = byte_stream_t{ o.transport };
                    o.state = ws_connection_state::closed;
                }
                return *this;
            }

            void tick() {

                if constexpr (HandshakePolicy::enabled && HandshakePolicy::is_initiator) {
                    if (state == ws_connection_state::handshake 
                        && !handshake.request_sent) {
                        auto req = handshake.build_request();
                        stream.write(req.data(), req.size());
                        handshake.request_sent = true;
                        return;
                    }
                }

                // ⛔ CLOSED: nada
                if (state == ws_connection_state::closed)
                    return;

                // 🔥 CLOSING: timeout SIEMPRE progresa
                //if (state == ws_connection_state::closing) {
                //    if (now - close_sent_at > std::chrono::seconds(5)) {
                //        //stream.transport->close();   // HARD CLOSE
                //        state = ws_connection_state::closed;
                //    }
                //    return;
                //}

                // ⬇️ SOLO OPEN LLEGA AQUÍ
                if (state != ws_connection_state::open)
                    return;

                if (!outbox.empty())
                    flush_outbox();

                /*if (now - last_rx > std::chrono::seconds(30)) {
                    send_close(ws_close_code::going_away);
                    return;
                }*/

                /*if (now - last_ping > std::chrono::seconds(10)) {
                    ws_send_frame<byte_stream_t, Role>(stream, ws_opcode::ping, nullptr, 0);
                    last_ping = now;
                }*/
            }

            void send_text(std::string_view msg) {
                pending_msg m{ .is_text = true };
                m.data.assign(msg.data(), msg.data() + msg.size());
                outbox.push_back(std::move(m));
            }

            void send_binary(binary_view b) {
                pending_msg m{ .is_text = false };
                m.data.assign(b.data(), b.data() + b.size());
                outbox.push_back(std::move(m));
            }

            void flush_outbox() {
                for (auto& m : outbox)
                    ws_send_frame<byte_stream_t, Role>(stream,
                        m.is_text ? ws_opcode::text : ws_opcode::binary,
                        m.data.data(), m.data.size());
                outbox.clear();
            }

            ws_step step_frame_header() {
                if (ws.phase != ws_phase::frame_header)
                    return ws_step::idle;

                auto fr = try_parse_frame_header<Role>(rb, ws);

                if (fr == frame_result::too_big) {
                    send_close(ws_close_code::message_too_big);
                    state = ws_connection_state::closed;
                    return ws_step::closed;
                }

                if (fr == frame_result::protocol_error) {
                    send_close(ws_close_code::protocol_error);
                    state = ws_connection_state::closed;
                    return ws_step::closed;
                }

                return ws_step::idle;
            }

            ws_step step_frame_payload() {
                if (ws.phase != ws_phase::frame_payload)
                    return ws_step::idle;

                std::vector<std::uint8_t> payload;
                if (try_read_frame_payload(rb, ws, payload) != frame_result::frame_ready)
                    return ws_step::idle;

                return handle_frame(payload);
            }

            ws_step handle_frame(std::vector<std::uint8_t>& payload) {
                //last_rx = std::chrono::steady_clock::now();
                bool is_known =
                    ws.opcode == ws_opcode::continuation ||
                    ws.opcode == ws_opcode::text ||
                    ws.opcode == ws_opcode::binary ||
                    ws.opcode == ws_opcode::close ||
                    ws.opcode == ws_opcode::ping ||
                    ws.opcode == ws_opcode::pong;

                if (!is_known) {
                    // Opcode reservado o desconocido → 1002 Protocol error
                    send_close(ws_close_code::protocol_error);
                    state = ws_connection_state::closed;
                    return ws_step::closed;
                }

                if ((ws.opcode == ws_opcode::ping ||
                    ws.opcode == ws_opcode::pong ||
                    ws.opcode == ws_opcode::close) && !ws.fin) {
                    // Control frames MUST NOT be fragmented
                    send_close(ws_close_code::protocol_error);
                    state = ws_connection_state::closed;
                    return ws_step::closed;
                }

                switch (ws.opcode) {
                case ws_opcode::ping:
                    send_pong(payload);
                    return ws_step::idle;

                case ws_opcode::pong:
                    return ws_step::idle;

                case ws_opcode::close: {
                    if (payload.size() >= 2) {
                        close_code =
                            ws_close_code((payload[0] << 8) |
                                payload[1]);
                    }
                    else {
                        close_code = ws_close_code::normal;
                    }

                    send_close();
                    state = ws_connection_state::closed;
                    return ws_step::closed;
                }

                default:
                    return assemble_message(payload);
                }
            }

            ws_step assemble_message(std::vector<std::uint8_t>& payload) {
                if ((ws.opcode == ws_opcode::continuation && !ws.fragmented) ||
                    (ws.opcode != ws_opcode::continuation && ws.fragmented)) {
                    send_close(ws_close_code::protocol_error);
                    state = ws_connection_state::closed;
                    return ws_step::closed;
                }

                if (ws.opcode != ws_opcode::continuation) {
                    ws.msg_opcode = ws.opcode;
                    ws.msg_buffer.clear();
                    ws.fragmented = !ws.fin;
                }

                // Message limit validation before 
                // we even allocate memory.. so we
                // gurantee it wont past the limit
                if (ws.msg_buffer.size() + payload.size() > MAX_MESSAGE_SIZE)
                {
                    // At this point limit violated.. 
                    // closing the connection
                    ws_send_close<byte_stream_t, Role>(
                        stream, ws_close_code::message_too_big);
                    state = ws_connection_state::closed;
                    return ws_step::closed;
                }

                ws.msg_buffer.insert(ws.msg_buffer.end(),
                    payload.begin(), payload.end());

                if (ws.msg_opcode == ws_opcode::text &&
                    !ws.utf8.feed((const uint8_t*)payload.data(),
                        payload.size())) {
                    send_close(ws_close_code::invalid_payload);
                    state = ws_connection_state::closed;
                    return ws_step::closed;
                }

                if (!ws.fin)
                    return ws_step::idle;

                if (ws.msg_opcode == ws_opcode::text) {
                    if (!ws.utf8.finished()) {
                        send_close(ws_close_code::invalid_payload);
                        state = ws_connection_state::closed;
                        return ws_step::closed;
                    }
                    ws.utf8.reset();
                }

                message.swap(ws.msg_buffer);
                message_opcode = ws.msg_opcode;
                ws.msg_buffer.clear();
                ws.fragmented = false;

                return ws_step::message;
            }

            void on_bytes(const char* data, size_t n) {
                rb.append(data, (int)n);
            }

            ws_step consume() {
                if constexpr (HandshakePolicy::enabled) {
                    if (state == ws_connection_state::handshake) {
                        if (!handshake.try_consume(rb, ws, state))
                            return ws_step::idle;

                        if constexpr (!HandshakePolicy::is_initiator)
                        {
                            auto& resposne = handshake.response;
                            if (!resposne.empty()) stream.write(
                                resposne.data(), resposne.size());
                        }

                        flush_outbox();
                    }
                }

                if (ws.phase == ws_phase::frame_header) {
                    auto r = try_parse_frame_header<Role>(rb, ws);
                    if (r == frame_result::protocol_error) return ws_step::error;
                    if (r != frame_result::frame_ready) return ws_step::idle;
                }

                if (ws.phase == ws_phase::frame_payload) {
                    std::vector<std::uint8_t> payload;
                    if (try_read_frame_payload(rb, ws, payload) != frame_result::frame_ready)
                        return ws_step::idle;

                    return handle_frame(payload);
                }

                return ws_step::idle;
            }

            void send_close(ws_close_code code = ws_close_code::normal) {
                if (state == ws_connection_state::open) {
                    ws_send_close<byte_stream_t, Role>(stream, code);
                    //close_sent_at = std::chrono::steady_clock::now();
                    state = ws_connection_state::closing;
                }
            }

            void send_pong(const std::vector<std::uint8_t>& payload) {
                ws_send_frame<byte_stream_t, Role>(stream, ws_opcode::pong,
                    payload.data(), payload.size());
            }
        };

        template<class Stream>
        struct reactor {
            fd_set rfds;
            fd_set wfds;
            std::vector<Stream*> streams;

            void add(Stream& s) {
                streams.push_back(&s);
            }

            template<class Fn>
            void tick(Fn&& on_read) {
                FD_ZERO(&rfds);
                FD_ZERO(&wfds);

                socket_t maxfd = 0;
                bool have_fds = false;

                for (auto* s : streams) {
                    if (!s->is_open())
                        continue;

                    socket_t h = s->handle();
                    if (h < 0)
                        continue;

                    FD_SET(h, &rfds);

                    if (s->wants_write())
                        FD_SET(h, &wfds);

                    if (!have_fds || h > maxfd)
                        maxfd = h;

                    have_fds = true;
                }

                if (!have_fds)
                    return;

                timeval tv{ 0, 0 };

#ifdef _WIN32
                // nfds ignored on Windows, but must be non-zero
                int r = ::select(0, &rfds, &wfds, nullptr, &tv);
#else
                int r = ::select(maxfd + 1, &rfds, &wfds, nullptr, &tv);
#endif
                if (r <= 0)
                    return;

                for (auto* s : streams) {
                    if (!s->is_open())
                        continue;

                    socket_t h = s->handle();
                    if (h < 0)
                        continue;

                    if (FD_ISSET(h, &wfds)) {
                        s->on_writable();   // connect / TLS completion
                        s->flush();         // optional; no-op if unused
                    }

                    if (FD_ISSET(h, &rfds)) {
                        on_read(*s);
                    }
                }
            }
        };

        // For Single FD FAST PATH POLL
        struct poll_rw {
            bool readable;
            bool writable;
        };

        inline poll_rw poll_fd(socket_t fd, bool want_write = false) {
            fd_set rfds, wfds;
            FD_ZERO(&rfds);
            FD_ZERO(&wfds);

            FD_SET(fd, &rfds);
            if (want_write)
                FD_SET(fd, &wfds);

            timeval tv{ 0, 0 };

#ifdef _WIN32
            int r = ::select(0, &rfds, &wfds, nullptr, &tv);
#else
            int r = ::select(fd + 1, &rfds, &wfds, nullptr, &tv);
#endif

            if (r <= 0)
                return { false, false };

            return {
                (bool)FD_ISSET(fd, &rfds),
                want_write && FD_ISSET(fd, &wfds)
            };
        }

        struct ws_url {
            bool secure = false;
            std::string host;
            std::string port;
            std::string default_port;
            std::string path;
            bool ok = false;

            bool has_default_port() const
            {
                return default_port == port;
            }
        };

        inline ws_url parse_ws_url(std::string_view in) {
            ws_url out{};

            auto trim = [](std::string_view& s) {
                while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
                    s.remove_prefix(1);
                while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
                    s.remove_suffix(1);
                };

            trim(in);
            if (in.empty()) return out;

            auto starts_ci = [](std::string_view s, std::string_view p) {
                if (s.size() < p.size()) return false;
                for (size_t i = 0; i < p.size(); ++i)
                    if (std::tolower((unsigned char)s[i]) != std::tolower((unsigned char)p[i]))
                        return false;
                return true;
                };

            // ---- scheme ----
            if (starts_ci(in, "wss://")) {
                out.secure = true;
                out.port = out.default_port = "443";
                in.remove_prefix(6);
            }
            else if (starts_ci(in, "ws://")) {
                out.secure = false;
                out.port = out.default_port = "80";
                in.remove_prefix(5);
            }
            else {
                return out;
            }

            if (in.empty()) return out;

            // ---- split path/query/fragment ----
            auto path_pos = in.find_first_of("/?#");
            std::string_view authority = in.substr(0, path_pos);
            out.path = (path_pos == std::string_view::npos)
                ? "/"
                : std::string(in.substr(path_pos));

            if (authority.empty()) return out;

            // ---- userinfo explicitly rejected ----
            if (authority.find('@') != std::string_view::npos)
                return out;

            // ---- host / port ----
            if (authority.front() == '[') {
                // IPv6 literal
                auto rb = authority.find(']');
                if (rb == std::string_view::npos) return out;

                out.host = std::string(authority.substr(1, rb - 1));

                if (rb + 1 < authority.size()) {
                    if (authority[rb + 1] != ':') return out;
                    out.port = std::string(authority.substr(rb + 2));
                }
            }
            else {
                auto colon = authority.find(':');
                if (colon != std::string_view::npos) {
                    out.host = std::string(authority.substr(0, colon));
                    out.port = std::string(authority.substr(colon + 1));
                }
                else {
                    out.host = std::string(authority);
                }
            }

            if (out.host.empty() || out.port.empty())
                return out;

            // ---- port validation ----
            for (char c : out.port)
                if (!std::isdigit((unsigned char)c))
                    return out;

            unsigned long p = std::strtoul(out.port.c_str(), nullptr, 10);
            if (p == 0 || p > 65535)
                return out;

            out.ok = true;
            return out;
        }

        struct wspp_runtime {
            wspp_runtime() {
#ifdef _WIN32
                WSADATA wsa;
                WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
#ifdef WSPP_USE_OPENSSL
                SSL_library_init();
                SSL_load_error_strings();
                OpenSSL_add_ssl_algorithms();
#endif
            }

            ~wspp_runtime() {
#ifdef WSPP_USE_OPENSSL
                EVP_cleanup();
#endif
#ifdef _WIN32
                WSACleanup();
#endif
            }

            static void ensure() {
                static std::once_flag flag;
                std::call_once(flag, [] {
                    static wspp_runtime rt;
                    });
            }
        };

        inline bool supports_wss() {
#ifdef WSPP_USE_OPENSSL
            return true;
#else
            return false;
#endif
        }

        enum class ws_connect_result {
            ok,                 // connected or connection in progress
            invalid_url,        // parse_ws_url failed
            tls_not_supported,  // wss:// but OpenSSL disabled
            connector_error,    // TCP/TLS connect failed
        };

        struct message_view {
            bool is_text_;
            binary_view data_view;

            bool is_text() const {
                return is_text_;
            }

            bool is_binary() const {
                return !is_text_;
            }

            std::string_view text() const {
                return is_text()
                    ? std::string_view((const char*)data_view.data(), 
                        data_view.size())
                    : std::string_view{};
            }

            binary_view binary() const {
                return is_binary()
                    ? data_view
                    : binary_view{};
            }
        };

        template <
            typename Connector, 
            typename Transport,
            typename Role = ws_client_role, 
            typename HandshakePolicy = client_handshake>
        struct basic_client {
            ws_endpoint<Transport, Role, HandshakePolicy> impl{ };

            Connector connector;
            std::function<void(message_view)> on_message_cb;
            std::function<void(ws_close_code)> on_close_cb;

            ws_connect_result connect(std::string_view url) {
                auto u = parse_ws_url(url);

                if (!u.ok)
                    return ws_connect_result::invalid_url;

                if (u.secure && !supports_wss())
                    return ws_connect_result::tls_not_supported;

                auto sock = connector.connect(u.host.c_str(), u.port.c_str());
                if (!sock.has_value())
                    return ws_connect_result::connector_error;
                impl.transport = std::move(sock.value());
                auto& hsk = impl.handshake;
                hsk.host = !u.has_default_port() ? (u.host + ":" + u.port) 
                    : u.host;
                hsk.path = u.path;
                impl.tick(); 
                // FIX ASYNC
                impl.stream.flush(); // Early Flushing Handshake
                return ws_connect_result::ok;
            }

            void send(std::string_view s) {
                impl.send_text(s);
            }

            void send(binary_view b) {
                impl.send_binary(b);
            }

            void close()
            {
                impl.send_close();
            }

            void close(ws_close_code code)
            {
                impl.send_close(
                    normalize_close_code(code));
            }

            void send(message_view msg) {
                if (msg.is_text())
                    impl.send_text(msg.text());
                else
                    impl.send_binary(msg.binary());
            }

            void on_message(auto cb) { on_message_cb = cb; }
            void on_close(auto cb) { on_close_cb = cb; }

            wspp_event poll() {
                auto& strm = impl.stream;

                impl.tick();

                if (poll_fd(strm.handle()).readable)
                {
                    // READ
                    char buf[2048];
                    auto r = strm.read(buf, sizeof(buf));
                    if (r.result == io_result::ok)
                        impl.on_bytes(buf, r.bytes);

                    // CONSUME
                    while (true) {
                        ws_step st = impl.consume();
                        if (st == ws_step::idle) break;

                        if (st == ws_step::message) {
                            if (on_message_cb) {
                                on_message_cb(message_view{
                                    impl.message_opcode == ws_opcode::text,
                                    binary_view{ impl.message }
                                    });
                            }
                        }

                        if (st == ws_step::closed || 
                            st == ws_step::error) {
                            if (on_close_cb)
                                on_close_cb(impl.close_code);

                            if (st == ws_step::error) 
                                return wspp_event::error;

                            return wspp_event::closed;
                        }
                    }
                }

                strm.flush();

                return wspp_event::idle;
            }

            /* Hard Close requested by the user */
            void abort()
            {
                // TO IMPLEMENT
            }

            void run() {
                while (true) {
                    auto e = poll();
                    if (e == wspp_event::closed ||
                        e == wspp_event::error)
                        break;
                }
            }
        };

        template<
            typename Acceptor,
            typename Transport,
            typename Role = ws_server_role,
            typename HandshakePolicy = server_handshake
        >
        struct basic_server {
            using endpoint_t = ws_endpoint<
                Transport,
                Role,
                HandshakePolicy
            >;

            // =========================
            // connection (user-facing)
            // =========================
            struct connection {
                endpoint_t ep;

                std::function<void(message_view)> on_message_cb;
                std::function<void(ws_close_code)> on_close_cb;

                // ---- user API (mirrors basic_client) ----
                void send(message_view msg) {
                    if (msg.is_text())
                        ep.send_text(msg.text());
                    else
                        ep.send_binary(msg.binary());
                }

                void send(std::string_view s) {
                    ep.send_text(s);
                }

                void send(binary_view b) {
                    ep.send_binary(b);
                }

                void close() {
                    ep.send_close();
                }

                void close(ws_close_code code) {
                    ep.send_close(code);
                }

                void on_message(auto cb) { on_message_cb = cb; }
                void on_close(auto cb) { on_close_cb = cb; }

                // ---- internal dispatch ----
                void dispatch_message() {
                    if (on_message_cb) {
                        on_message_cb(message_view{
                            ep.message_opcode == ws_opcode::text,
                            binary_view{ ep.message }
                            });
                    }
                }

                void dispatch_close() {
                    if (on_close_cb)
                        on_close_cb(ep.close_code);
                }

                bool is_alive() const {
                    // TODO
                    return true; //ep.is_alive();
                }
            };

            using connection_ptr = std::shared_ptr<connection>;

            // =========================
            // server state
            // =========================
            Acceptor acceptor;
            std::vector<connection_ptr> connections;

            std::function<void(connection_ptr)> on_connection_cb;

            // =========================
            // API
            // =========================
            bool listen(uint16_t port) {
                wspp_runtime::ensure();
                return acceptor.bind_and_listen(port);
            }

            void on_connection(auto cb) {
                on_connection_cb = cb;
            }

            // =========================
            // event loop
            // =========================
            void poll() {
                // 1) accept
                while (auto sock = acceptor.try_accept()) {
                    auto conn = std::make_shared<connection>();
                    conn->ep.transport = std::move(*sock);

                    connections.push_back(conn);

                    if (on_connection_cb)
                        on_connection_cb(conn);
                }

                // 2) protocol produce
                for (auto& c : connections)
                    c->ep.tick();

                // 3) IO + consume
                for (auto& c : connections) {
                    auto& ep = c->ep;
                    auto& s = ep.stream;

                    // TODO.. Reactor for parallel polling with reactor
                    if (!poll_fd(s.handle()).readable)
                        continue;

                    char buf[2048];
                    auto r = s.read(buf, sizeof(buf));
                    if (r.result == io_result::ok)
                        ep.on_bytes(buf, r.bytes);

                    while (true) {
                        ws_step st = ep.consume();
                        if (st == ws_step::idle)
                            break;

                        if (st == ws_step::message)
                            c->dispatch_message();

                        if (st == ws_step::closed || st == ws_step::error) {
                            c->dispatch_close();
                            break;
                        }
                    }
                }

                // 4) flush
                for (auto& c : connections)
                    c->ep.stream.flush();

                // 5) cleanup
                std::erase_if(connections,
                    [](const connection_ptr& c) {
                        return !c->is_alive();
                    });
            }

            void run() {
                while (true)
                    poll();
            }
        };
    }

    using message_view = detail::message_view;
    using binary_view = detail::binary_view;
    using ws_close_code = detail::ws_close_code;
    using ws_client = detail::basic_client<detail::tcp_connector, detail::tcp_socket>;
    using ws_server = detail::basic_server<detail::tcp_acceptor, detail::tcp_socket>;
#ifdef WSPP_USE_OPENSSL
    using wss_client = detail::basic_client<detail::tls_connector<detail::openssl_client_policy>, detail::tls_socket>;
    // TODO
    // using wss_server = ...;
#endif
}