#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_tostring.hpp>
#include <string_view>
#include <wspp/wspp.h>

using wspp::detail::parse_ws_url;
using wspp::detail::ws_url;

struct UrlCase {
    std::string_view input;
    bool ok;
    bool secure;
    std::string_view host;
    std::string_view port;
    std::string_view path;
};

TEST_CASE("parse_ws_url parses valid websocket urls") {
    const UrlCase cases[] = {
        // ---- basic ----
        { "ws://example.com",        true,  false, "example.com", "80",  "/" },
        { "wss://example.com",       true,  true,  "example.com", "443", "/" },

        // ---- path ----
        { "ws://example.com/chat",   true,  false, "example.com", "80",  "/chat" },
        { "wss://x/y/z",             true,  true,  "x",           "443", "/y/z" },

        // ---- explicit port ----
        { "ws://example.com:8080",   true,  false, "example.com", "8080", "/" },
        { "wss://example.com:8443/", true,  true,  "example.com", "8443", "/" },

        // ---- ipv6 ----
        { "ws://[::1]",              true,  false, "::1", "80",  "/" },
        { "wss://[2001:db8::1]:9000",
                                   true,  true,  "2001:db8::1", "9000", "/" },
    };

    for (const auto& c : cases) {
        INFO("url = " << c.input);
        auto u = parse_ws_url(c.input);

        REQUIRE(u.ok == c.ok);
        if (!c.ok) continue;

        REQUIRE(u.secure == c.secure);
        REQUIRE(u.host == c.host);
        REQUIRE(u.port == c.port);
        REQUIRE(u.path == c.path);
    }
}

TEST_CASE("parse_ws_url rejects invalid websocket urls") {
    const std::string_view invalid[] = {
        "",                         // empty
        "http://example.com",       // wrong scheme
        "https://example.com",      // wrong scheme
        "ws://",                    // no host
        "ws:///path",               // empty authority
        "ws://:80",                 // empty host
        "ws://host:",               // empty port
        "ws://host:abc",            // non-numeric port
        "ws://host:0",              // invalid port
        "ws://host:70000",          // port overflow
        "ws://user@host",           // userinfo forbidden
        "ws://[::1",                // broken ipv6
        "ws://[::1]x",              // garbage after ipv6
        "ws://[::1]:",              // empty ipv6 port
        "ws://[::1]:abc",           // invalid ipv6 port
    };

    for (auto url : invalid) {
        INFO("url = " << url);
        REQUIRE_FALSE(parse_ws_url(url).ok);
    }
}

TEST_CASE("parse_ws_url trims whitespace") {
    auto u = parse_ws_url("   ws://example.com/chat   ");
    REQUIRE(u.ok);
    REQUIRE(u.host == "example.com");
    REQUIRE(u.path == "/chat");
}

