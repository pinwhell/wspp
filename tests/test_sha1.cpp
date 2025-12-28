#include <catch2/catch_test_macros.hpp>
#include <array>
#include <string>
#include <vector>

#include <wspp/wspp.h>

using wspp::detail::sha1_digest;

struct Sha1Case {
    std::string input;
    std::array<uint8_t, 20> digest;
};

TEST_CASE("sha1_digest matches official test vectors (RFC 3174)") {
    const Sha1Case cases[] = {
        {
            "",
            { 0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,
              0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09 }
        },
        {
            "abc",
            { 0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,
              0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d }
        },
        {
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            { 0x84,0x98,0x3e,0x44,0x1c,0x3b,0xd2,0x6e,0xba,0xae,
              0x4a,0xa1,0xf9,0x51,0x29,0xe5,0xe5,0x46,0x70,0xf1 }
        }
    };

    for (const auto& c : cases) {
        INFO("input size = " << c.input.size());

        auto out = sha1_digest(
            reinterpret_cast<const uint8_t*>(c.input.data()),
            c.input.size()
        );

        REQUIRE(out == c.digest);
    }
}

TEST_CASE("sha1_digest handles binary data correctly") {
    const std::vector<uint8_t> binary = {
        0x00, 0x01, 0x02, 0xFF, 0x10, 0x20, 0x30
    };

    auto out = sha1_digest(binary.data(), binary.size());

    // Known-good computed externally
    const std::array<uint8_t, 20> expected = {
        0x53, 0x87, 0xc8, 0x07, 0x71, 0xf1, 0xf6, 0x3f, 0x06, 0x96,
        0x54, 0x48, 0x97, 0x6b, 0xa0, 0x10, 0x0b, 0xb3, 0xa0, 0x58
    };

    REQUIRE(out == expected);
}

TEST_CASE("sha1_digest is deterministic") {
    const std::string input = "determinism check";

    auto a = sha1_digest(
        reinterpret_cast<const uint8_t*>(input.data()),
        input.size()
    );
    auto b = sha1_digest(
        reinterpret_cast<const uint8_t*>(input.data()),
        input.size()
    );

    REQUIRE(a == b);
}