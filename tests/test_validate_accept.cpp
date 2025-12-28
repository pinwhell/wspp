#include <catch2/catch_test_macros.hpp>
#include <string>
#include <wspp/wspp.h>  

using wspp::detail::validate_accept;

struct AcceptCase {
    std::string key;     // Sec-WebSocket-Key
    std::string accept;  // Sec-WebSocket-Accept
    bool        valid;
};

TEST_CASE("validate_accept matches official & proven RFC 6455 examples", "[websocket][handshake]") {
    const AcceptCase cases[] = {
        // ── 1. Official example from RFC 6455 §1.3 / §4.2.2 ─────────────────────────────
        {
            "dGhlIHNhbXBsZSBub25jZQ==",             // "the sample nonce"
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",          // correct
            true
        },

        // ── 2. Very common example (MDN, Wikipedia, many libraries) ─────────────────────
        {
            "x3JJHMbDL1EzLkh9GBhXDw==",
            "HSmrc0sMlYUkAGmm5OPpG2HaGWk=",
            true
        },

        // ── 3. Popular real-world key used in curl examples & many implementations ──────
        {
            "SGVsbG8sIHdvcmxkIQ==",                 // decodes to "Hello, world!"
            "qGEgH3En71di5rrssAZTmtRTyFk=",          // correct value 
            true
        },

        // ── 4. Another realistic key seen in various WebSocket test suites ──────────────
        {
            "fFBooB7FAkLl9H2r",
            "8mxmJIPmHtzmLE9w27B4y9XHQ14=",        
            true
        },

        // ── Negative cases ──────────────────────────────────────────────────────────────
        {
            "dGhlIHNhbXBsZSBub25jZQ==",             // correct key
            "S3pPLMBiTxaQ9kYGzzhZRbK+xOo=",          // wrong case → MUST fail
            false
        },
        {
            "MTIzNDU2Nzg5MDEyMzQ1Ng==",             // "1234567890123456"
            "mWqkxO92vIh0NGshCsM2ADK4rxg=",          // wrong accept
            false
        },
        {
            "",                                     // empty key → invalid
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            false
        },
        {
            "dGhlIHNhbXBsZSBub25jZQ==",             // correct key
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo",           // missing '=' padding
            false
        },
        {
            "dGhlIHNhbXBsZSBub25jZQ==",             // correct key
            "AAAAAAAAAAAAAAAAAAAAAAAAAAA=",          // random wrong value
            false
        },
    };

    for (const auto& c : cases) {
        INFO("Key    = " << c.key);
        INFO("Accept = " << c.accept);
        REQUIRE(validate_accept(c.key, c.accept) == c.valid);
    }
}

TEST_CASE("validate_accept is sensitive to small key changes", "[websocket][handshake]") {
    const std::string correct_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const std::string correct_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    // One char difference → completely different SHA-1 → must fail
    const std::string almost_same_key = "dGhlIHNhbXBsZSBub25jZA==";

    REQUIRE(validate_accept(correct_key, correct_accept));
    REQUIRE_FALSE(validate_accept(almost_same_key, correct_accept));
}