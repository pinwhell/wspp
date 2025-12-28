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


#ifdef WSPP_USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ws2_32.lib")
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

        constexpr auto MAX_FRAME_SIZE = 64 * 1024 * 1024;

        enum class io_result : int {
            fatal = -1,
            no_data = 0,
            ok = 1
        };

        enum class ws_client_state {
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

        struct tcp_stream {
            tcp_state state = tcp_state::closed;
            socket_t  sock = invalid_socket;

            tcp_stream() = default;
            ~tcp_stream() { close(); }

            tcp_stream(const tcp_stream&) = delete;
            tcp_stream& operator=(const tcp_stream&) = delete;

            tcp_stream(tcp_stream&& o) noexcept { *this = std::move(o); }
            tcp_stream& operator=(tcp_stream&& o) noexcept {
                if (this != &o) {
                    close();
                    sock = o.sock;
                    state = o.state;
                    o.sock = invalid_socket;
                    o.state = tcp_state::closed;
                }
                return *this;
            }

            bool connect(const char* host, const char* port) {
                state = tcp_state::connecting;

                addrinfo hints{};
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_protocol = IPPROTO_TCP;

                addrinfo* res = nullptr;
                if (::getaddrinfo(host, port, &hints, &res) != 0)
                    return false;

                sock = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                if (sock == invalid_socket) {
                    ::freeaddrinfo(res);
                    return false;
                }

                // BLOCKING CONNECT: TODO NON-BLOCKING
                int r = ::connect(sock, res->ai_addr, (int)res->ai_addrlen);

                set_non_blocking(sock);
                ::freeaddrinfo(res);

                if (r == 0) {
                    state = tcp_state::connected;
                    return true;
                }

                if (!would_block(last_error())) {
                    close();
                    return false;
                }

                return true;
            }

            void on_writable() {
                if (state != tcp_state::connecting) return;

                int err = 0;
                socklen_t len = sizeof(err);
                ::getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &len);

                if (err == 0)
                    state = tcp_state::connected;
                else
                    close();
            }

            int write(const void* data, int size) {
                return (int)::send(sock, (const char*)data, size, 0);
            }

            io_read read(void* data, int capacity) {
                int n = (int)::recv(sock, (char*)data, capacity, 0);
                if (n < 0) {
                    if (would_block(last_error()))
                        return { io_result::no_data, 0 };
                    return { io_result::fatal, 0 };
                }
                if (n == 0)
                    return { io_result::fatal, 0 }; // peer closed
                return { io_result::ok, n };
            }

            bool is_open()  const { return state == tcp_state::connected; }
            bool is_alive() const { return state != tcp_state::closed; }
            bool wants_write() const { return state == tcp_state::connecting; }

            void close() {
                if (sock != invalid_socket) {
                    socket_close(sock);
                    sock = invalid_socket;
                }
                state = tcp_state::closed;
            }

            socket_t handle() const { return sock; }
        };

#ifdef WSPP_USE_OPENSSL
        template<class Policy>
        struct tls_stream {
            SSL_CTX* ctx = nullptr;
            SSL* ssl = nullptr;
            BIO* bio = nullptr;
            socket_t sock = invalid_socket;
            bool     open = false;

            tls_stream() = default;
            ~tls_stream() { close(); }

            tls_stream(const tls_stream&) = delete;
            tls_stream& operator=(const tls_stream&) = delete;

            bool connect(const char* host, const char* port) {
                ctx = Policy::create_ctx();
                if (!ctx) return false;

                bio = BIO_new_ssl_connect(ctx);
                if (!bio) return false;

                BIO_get_ssl(bio, &ssl);
                if (!ssl) return false;

                SSL_set_tlsext_host_name(ssl, host);

                std::string target = std::string(host) + ":" + port;
                BIO_set_conn_hostname(bio, target.c_str());

                // ---- BLOCKING CONNECT + HANDSHAKE ----
                // TODO NON-BLOCKING
                BIO_set_nbio(bio, 0);

                if (BIO_do_connect(bio) <= 0)
                    return false;

                if (BIO_do_handshake(bio) <= 0)
                    return false;

                // Extract underlying socket
                int fd = -1;
                BIO_get_fd(bio, &fd);
                sock = (socket_t)fd;

                set_non_blocking(sock);
                BIO_set_nbio(bio, 1);

                open = true;
                return true;
            }

            void on_writable() {
                // TLS uses internal buffering; no state machine needed here
            }

            bool wants_write() const {
                return false;
            }

            io_read read(void* buf, int cap) {
                if (!open) return { io_result::fatal, 0 };

                int ret = BIO_read(bio, buf, cap);

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

            int write(const void* buf, int len) {
                if (!open) return -1;

                int r = BIO_write(bio, buf, len);
                if (r > 0)
                    return r;

                if (BIO_should_retry(bio))
                    return 0;

                return -1;
            }

            bool is_open() const {
                return open;
            }

            bool is_alive() const {
                return bio && sock != invalid_socket;
            }

            socket_t handle() const {
                return sock;
            }

            void close() {
                if (bio) {
                    BIO_free_all(bio);
                    bio = nullptr;
                }

                if (ctx) {
                    SSL_CTX_free(ctx);
                    ctx = nullptr;
                }

                if (sock != invalid_socket) {
                    socket_close(sock);
                    sock = invalid_socket;
                }

                ssl = nullptr;
                open = false;
            }
        };
#endif

        template<class Transport>
        struct byte_stream {
            Transport& t;
            std::vector<char> out;

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
            std::vector<char> buf;

            void append(const char* data, int n) {
                buf.insert(buf.end(), data, data + n);
            }

            int find(const char* seq, int len) const {
                for (size_t i = 0; i + len <= buf.size(); ++i) {
                    if (std::memcmp(buf.data() + i, seq, len) == 0)
                        return (int)i;
                }
                return -1;
            }

            void consume(int n) {
                buf.erase(buf.begin(), buf.begin() + n);
            }

            const char* data() const { return buf.data(); }
            int size() const { return (int)buf.size(); }
        };

        enum class ws_phase {
            frame_header,
            frame_payload,
            closed
        };

        struct ws_state {
            ws_phase phase = ws_phase::frame_header;
            ws_opcode opcode = ws_opcode::continuation;
            bool fin = false;
            bool fragmented = false;
            uint64_t payload_len = 0;
            uint8_t mask_key[4]{};

            ws_opcode msg_opcode = ws_opcode::continuation;    // 🔑 opcode real
            std::vector<char> msg_buffer;        // 🔑 acumulador
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

            int header_size = 2;

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

        frame_result try_read_frame_payload(read_buffer& rb, ws_state& ws,
            std::vector<char>& out_payload) {
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

        std::string base64_encode(const uint8_t* data, size_t len) {
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

        int base64_value(char c) {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
        }

        bool base64_decode(const std::string& in, std::vector<uint8_t>& out) {
            if (in.size() % 4 != 0)
                return false;

            out.clear();
            out.reserve((in.size() / 4) * 3);

            for (size_t i = 0; i < in.size(); i += 4) {
                uint32_t v = 0;
                int pad = 0;

                for (int j = 0; j < 4; ++j) {
                    char c = in[i + j];
                    if (c == '=') {
                        v <<= 6;
                        ++pad;
                    }
                    else {
                        int x = base64_value(c);
                        if (x < 0) return false;
                        v = (v << 6) | x;
                    }
                }

                for (int j = 0; j < 3 - pad; ++j)
                    out.push_back((v >> (16 - j * 8)) & 0xFF);
            }

            return true;
        }

        struct sha1_ctx {
            uint32_t h[5];
            uint64_t len_bits;
            uint8_t buf[64];
            size_t buf_len;
        };

        uint32_t rol(uint32_t x, uint32_t n) {
            return (x << n) | (x >> (32 - n));
        }

        void sha1_init(sha1_ctx& ctx) {
            ctx.h[0] = 0x67452301;
            ctx.h[1] = 0xEFCDAB89;
            ctx.h[2] = 0x98BADCFE;
            ctx.h[3] = 0x10325476;
            ctx.h[4] = 0xC3D2E1F0;
            ctx.len_bits = 0;
            ctx.buf_len = 0;
        }


        void sha1_process_block(sha1_ctx& ctx, const uint8_t block[64]) {
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

        void sha1_update(sha1_ctx& ctx, const uint8_t* data, size_t len) {
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

        void sha1_final(sha1_ctx& ctx, uint8_t out[20]) {
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

        std::array<uint8_t, 20> sha1_digest(const uint8_t* data, size_t len) {
            sha1_ctx ctx{};
            sha1_init(ctx);
            sha1_update(ctx, data, len);

            std::array<uint8_t, 20> out{};
            sha1_final(ctx, out.data());
            return out;
        }

        bool validate_accept(const std::string& key,
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

        bool parse_http_handshake(read_buffer& rb, http_handshake& out)
        {
            const char* buf = rb.data();
            int len = rb.size();

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

        struct pending_msg {
            std::vector<char> data;
        };

        bool is_valid_utf8(const std::vector<char>& data) {
            const uint8_t* s = (const uint8_t*)data.data();
            size_t i = 0, n = data.size();

            while (i < n) {
                uint8_t c = s[i];

                if (c <= 0x7F) {
                    i++;
                }
                else if ((c & 0xE0) == 0xC0) {
                    if (i + 1 >= n) return false;
                    if (c < 0xC2) return false;
                    if ((s[i + 1] & 0xC0) != 0x80) return false;
                    i += 2;
                }
                else if ((c & 0xF0) == 0xE0) {
                    if (i + 2 >= n) return false;
                    if ((s[i + 1] & 0xC0) != 0x80 ||
                        (s[i + 2] & 0xC0) != 0x80)
                        return false;

                    uint32_t cp =
                        ((c & 0x0F) << 12) |
                        ((s[i + 1] & 0x3F) << 6) |
                        (s[i + 2] & 0x3F);

                    if (cp < 0x800) return false;
                    if (cp >= 0xD800 && cp <= 0xDFFF) return false;

                    i += 3;
                }
                else if ((c & 0xF8) == 0xF0) {
                    if (i + 3 >= n) return false;
                    if ((s[i + 1] & 0xC0) != 0x80 ||
                        (s[i + 2] & 0xC0) != 0x80 ||
                        (s[i + 3] & 0xC0) != 0x80)
                        return false;

                    uint32_t cp =
                        ((c & 0x07) << 18) |
                        ((s[i + 1] & 0x3F) << 12) |
                        ((s[i + 2] & 0x3F) << 6) |
                        (s[i + 3] & 0x3F);

                    if (cp < 0x10000 || cp > 0x10FFFF)
                        return false;

                    i += 4;
                }
                else {
                    return false;
                }
            }

            return true;
        }

        template <typename ByteStream, typename Role>
        void ws_send_close(ByteStream& stream, ws_close_code code) {
            uint16_t be = htons(static_cast<uint16_t>(code));
            ws_send_frame<ByteStream, Role>(stream, ws_opcode::close, &be, 2);
        }

        bool handle_close_payload(const std::vector<char>& payload) {
            if (payload.empty())
                return true;

            if (payload.size() == 1)
                return false; // RFC: invalid

            uint16_t code =
                (uint8_t(payload[0]) << 8) |
                uint8_t(payload[1]);

            if (code < 1000 ||
                code == 1004 || code == 1005 || code == 1006 ||
                (code >= 1016 && code <= 2999))
                return false;

            if (payload.size() > 2) {
                std::vector<char> reason(payload.begin() + 2, payload.end());
                if (!is_valid_utf8(reason))
                    return false;
            }

            return true;
        }

        template<typename Transport>
        struct ws_client {
            using byte_stream_t = byte_stream<Transport>;

            std::string ws_key;
            byte_stream_t& stream;
            read_buffer rb;
            ws_state ws;
            ws_client_state state = ws_client_state::handshake;
            std::vector<pending_msg> outbox;
            std::vector<char> message;
            ws_opcode message_opcode = ws_opcode::continuation;
            std::chrono::steady_clock::time_point last_rx;
            std::chrono::steady_clock::time_point last_ping;
            ws_close_code close_code = ws_close_code::normal;
            std::chrono::steady_clock::time_point close_sent_at;
            bool close_reported = false;

            explicit ws_client(byte_stream_t& s, std::string key)
                : stream(s), ws_key(std::move(key)) {
            }

            void produce() {
                auto now = std::chrono::steady_clock::now();

                // ⛔ CLOSED: nada
                if (state == ws_client_state::closed)
                    return;

                // 🔥 CLOSING: timeout SIEMPRE progresa
                if (state == ws_client_state::closing) {
                    if (now - close_sent_at > std::chrono::seconds(5)) {
                        //stream.transport->close();   // HARD CLOSE
                        state = ws_client_state::closed;
                    }
                    return;
                }

                // ⬇️ SOLO OPEN LLEGA AQUÍ
                if (state != ws_client_state::open)
                    return;

                if (!outbox.empty())
                    flush_outbox();

                if (now - last_rx > std::chrono::seconds(30)) {
                    ws_send_close<byte_stream_t, ws_client_role>(stream, ws_close_code::going_away);
                    close_sent_at = now;
                    state = ws_client_state::closing;
                    return;
                }

                if (now - last_ping > std::chrono::seconds(10)) {
                    ws_send_frame<byte_stream_t, ws_client_role>(stream, ws_opcode::ping, nullptr, 0);
                    last_ping = now;
                }
            }

            void send_text(std::string_view msg) {
                pending_msg m;
                m.data.assign(msg.data(), msg.data() + msg.size());
                outbox.push_back(std::move(m));
            }

            void flush_outbox() {
                for (auto& m : outbox)
                    ws_send_frame<byte_stream_t, ws_client_role>(stream, ws_opcode::text,
                        m.data.data(), m.data.size());
                outbox.clear();
            }

            ws_step step_frame_header() {
                if (ws.phase != ws_phase::frame_header)
                    return ws_step::idle;

                auto fr = try_parse_frame_header<ws_client_role>(rb, ws);

                if (fr == frame_result::too_big) {
                    ws_send_close<byte_stream_t, ws_client_role>(stream, ws_close_code::message_too_big);
                    state = ws_client_state::closed;
                    return ws_step::closed;
                }

                if (fr == frame_result::protocol_error) {
                    ws_send_close<byte_stream_t, ws_client_role>(stream, ws_close_code::protocol_error);
                    state = ws_client_state::closed;
                    return ws_step::closed;
                }

                return ws_step::idle;
            }

            ws_step step_frame_payload() {
                if (ws.phase != ws_phase::frame_payload)
                    return ws_step::idle;

                std::vector<char> payload;
                if (try_read_frame_payload(rb, ws, payload) != frame_result::frame_ready)
                    return ws_step::idle;

                return handle_frame(payload);
            }

            ws_step handle_frame(std::vector<char>& payload) {
                last_rx = std::chrono::steady_clock::now();
                bool is_known =
                    ws.opcode == ws_opcode::continuation ||
                    ws.opcode == ws_opcode::text ||
                    ws.opcode == ws_opcode::binary ||
                    ws.opcode == ws_opcode::close ||
                    ws.opcode == ws_opcode::ping ||
                    ws.opcode == ws_opcode::pong;

                if (!is_known) {
                    // Opcode reservado o desconocido → 1002 Protocol error
                    ws_send_close<byte_stream_t, ws_client_role>(stream, ws_close_code::protocol_error);
                    state = ws_client_state::closed;
                    return ws_step::closed;
                }

                if ((ws.opcode == ws_opcode::ping ||
                    ws.opcode == ws_opcode::pong ||
                    ws.opcode == ws_opcode::close) && !ws.fin) {
                    // Control frames MUST NOT be fragmented
                    ws_send_close<byte_stream_t, ws_client_role>(stream, ws_close_code::protocol_error);
                    state = ws_client_state::closed;
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
                            ws_close_code((uint8_t(payload[0]) << 8) |
                                uint8_t(payload[1]));
                    }
                    else {
                        close_code = ws_close_code::normal;
                    }

                    send_close();
                    state = ws_client_state::closed;
                    return ws_step::closed;
                }

                default:
                    return assemble_message(payload);
                }
            }

            ws_step assemble_message(std::vector<char>& payload) {
                if ((ws.opcode == ws_opcode::continuation && !ws.fragmented) ||
                    (ws.opcode != ws_opcode::continuation && ws.fragmented)) {
                    ws_send_close<byte_stream_t, ws_client_role>(stream, ws_close_code::protocol_error);
                    state = ws_client_state::closed;
                    return ws_step::closed;
                }

                if (ws.opcode != ws_opcode::continuation) {
                    ws.msg_opcode = ws.opcode;
                    ws.msg_buffer.clear();
                    ws.fragmented = !ws.fin;
                }

                ws.msg_buffer.insert(ws.msg_buffer.end(),
                    payload.begin(), payload.end());

                if (!ws.fin)
                    return ws_step::idle;

                if (ws.msg_opcode == ws_opcode::text
                    && !is_valid_utf8(ws.msg_buffer)) {
                    ws_send_close<byte_stream_t, ws_client_role>(stream, ws_close_code::invalid_payload);
                    state = ws_client_state::closed;
                    return ws_step::closed;
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
                if (state == ws_client_state::handshake) {
                    http_handshake hs;
                    if (!parse_http_handshake(rb, hs))
                        return ws_step::idle;

                    if (!validate_accept(ws_key, hs.accept))
                        return ws_step::error;

                    rb.consume(hs.consumed);
                    state = ws_client_state::open;
                    last_rx = last_ping = std::chrono::steady_clock::now();
                    flush_outbox();
                    return ws_step::idle;
                }

                if (ws.phase == ws_phase::frame_header) {
                    auto r = try_parse_frame_header<ws_client_role>(rb, ws);
                    if (r == frame_result::protocol_error) return ws_step::error;
                    if (r != frame_result::frame_ready) return ws_step::idle;
                }

                if (ws.phase == ws_phase::frame_payload) {
                    std::vector<char> payload;
                    if (try_read_frame_payload(rb, ws, payload) != frame_result::frame_ready)
                        return ws_step::idle;

                    return handle_frame(payload);
                }

                return ws_step::idle;
            }

            void send_close() {
                if (state == ws_client_state::open) {
                    ws_send_close<byte_stream_t, ws_client_role>(stream, ws_close_code::normal);
                    close_sent_at = std::chrono::steady_clock::now();
                    state = ws_client_state::closing;
                }
            }

            void send_pong(const std::vector<char>& payload) {
                ws_send_frame<byte_stream_t, ws_client_role>(stream, ws_opcode::pong,
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

                timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 0;

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

        std::string generate_ws_key() {
            uint8_t bytes[16];
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<uint16_t> dist(0, 255);
            for (auto& b : bytes) b = (uint8_t)dist(gen);
            return base64_encode(bytes, 16);
        }

        struct ws_url {
            bool secure = false;
            std::string host;
            std::string port;
            std::string path;
            bool ok = false;
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
                out.port = "443";
                in.remove_prefix(6);
            }
            else if (starts_ci(in, "ws://")) {
                out.secure = false;
                out.port = "80";
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
        bool supports_wss() {
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
            transport_error,    // TCP/TLS connect failed
        };

        template <class Transport>
        struct basic_client {
            using byte_stream_t = byte_stream<Transport>;
            Transport transport;
            byte_stream_t stream{ transport };
            ws_client<Transport> impl{ stream, generate_ws_key() };
            reactor<byte_stream_t> r;

            std::function<void(std::string_view)> on_text_cb;
            std::function<void(ws_close_code)> on_close_cb;

            ws_connect_result connect(std::string_view url) {
                wspp_runtime::ensure();

                auto u = parse_ws_url(url);

                if (!u.ok)
                    return ws_connect_result::invalid_url;

                if (u.secure && !supports_wss())
                    return ws_connect_result::tls_not_supported;

                if (!transport.connect(u.host.c_str(), u.port.c_str()))
                    return ws_connect_result::transport_error;

                std::string req =
                    "GET " + u.path + " HTTP/1.1\r\n"
                    "Host: " + u.host + "\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Key: " + impl.ws_key + "\r\n"
                    "Sec-WebSocket-Version: 13\r\n\r\n";

                stream.write(req.data(), req.size());
                r.add(stream);
                return ws_connect_result::ok;
            }

            void send(std::string_view s) {
                impl.send_text(s);
            }

            void on_text(auto cb) { on_text_cb = cb; }
            void on_close(auto cb) { on_close_cb = cb; }

            wspp_event poll() {
                wspp_event ev = wspp_event::idle;

                if (!transport.is_alive()) {
                    if (!impl.close_reported) {
                        impl.close_reported = true;
                        if (on_close_cb)
                            on_close_cb(impl.close_code); // timeout / implicit close
                    }
                    return wspp_event::closed;
                }

                // PRODUCE SIEMPRE (aunque no haya IO)
                impl.produce();

                r.tick([&](byte_stream_t& s) {

                    // READ
                    char buf[2048];
                    auto r = s.read(buf, sizeof(buf));
                    if (r.result == io_result::ok)
                        impl.on_bytes(buf, r.bytes);

                    // CONSUME
                    while (true) {
                        ws_step st = impl.consume();
                        if (st == ws_step::idle) break;

                        if (st == ws_step::message &&
                            impl.message_opcode == ws_opcode::text) {
                            if (on_text_cb)
                                on_text_cb({ impl.message.data(), impl.message.size() });
                        }

                        if (st == ws_step::closed) {
                            transport.close();

                            impl.close_reported = true;
                            if (on_close_cb)
                                on_close_cb(impl.close_code);

                            ev = wspp_event::closed;
                            return;
                        }

                        if (st == ws_step::error) {
                            transport.close();
                            ev = wspp_event::error;
                            return;
                        }
                    }

                    // FLUSH
                    s.flush();
                    });

                return ev;
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
    }

    using ws_close_code = detail::ws_close_code;
    using ws_client = detail::basic_client<detail::tcp_stream>;
#ifdef WSPP_USE_OPENSSL
    using wss_client = detail::basic_client<detail::tls_stream<detail::openssl_client_policy>>;
#endif
}