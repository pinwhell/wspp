#include <catch2/catch_test_macros.hpp>
#include <vector>
#include <string>

#include <wspp/wspp.h>

using wspp::detail::base64_encode;
using wspp::detail::base64_decode;

struct B64Case {
    std::string plain;
    std::string encoded;
};

TEST_CASE("base64_encode matches RFC 4648 test vectors") {
    const B64Case cases[] = {
        { "",        "" },
        { "f",       "Zg==" },
        { "fo",      "Zm8=" },
        { "foo",     "Zm9v" },
        { "foob",    "Zm9vYg==" },
        { "fooba",   "Zm9vYmE=" },
        { "foobar",  "Zm9vYmFy" },
    };

    for (const auto& c : cases) {
        INFO("plain = '" << c.plain << "'");
        auto out = base64_encode(
            reinterpret_cast<const uint8_t*>(c.plain.data()),
            c.plain.size()
        );
        REQUIRE(out == c.encoded);
    }
}

TEST_CASE("base64_decode matches RFC 4648 test vectors") {
    const B64Case cases[] = {
        { "",        "" },
        { "f",       "Zg==" },
        { "fo",      "Zm8=" },
        { "foo",     "Zm9v" },
        { "foob",    "Zm9vYg==" },
        { "fooba",   "Zm9vYmE=" },
        { "foobar",  "Zm9vYmFy" },
    };

    for (const auto& c : cases) {
        INFO("encoded = '" << c.encoded << "'");

        std::vector<uint8_t> out;
        REQUIRE(base64_decode(c.encoded, out));

        std::string decoded(out.begin(), out.end());
        REQUIRE(decoded == c.plain);
    }
}

TEST_CASE("base64 round-trip encode -> decode is lossless") {
    const std::string inputs[] = {
        "",
        "hello",
        "The quick brown fox jumps over the lazy dog",
        std::string(1000, 'x'),           // large payload
        std::string("\0\1\2\3\4", 5),      // binary data
    };

    for (const auto& s : inputs) {
        INFO("size = " << s.size());

        auto enc = base64_encode(
            reinterpret_cast<const uint8_t*>(s.data()),
            s.size()
        );

        std::vector<uint8_t> dec;
        REQUIRE(base64_decode(enc, dec));

        REQUIRE(std::equal(
            dec.begin(), dec.end(),
            reinterpret_cast<const uint8_t*>(s.data())
        ));
    }
}

TEST_CASE("base64_decode rejects invalid input") {
    const std::string invalid[] = {
        "Zg=",        // wrong padding
        "Zg===",      // too much padding
        "Zm=v",       // invalid char
        "Zm9",        // length % 4 != 0
        "####",       // garbage
    };

    for (const auto& s : invalid) {
        INFO("input = '" << s << "'");
        std::vector<uint8_t> out;
        REQUIRE_FALSE(base64_decode(s, out));
    }
}
