// TODO.. THIS IS GOOD ENOUGH FOR 
// NOW BUT IN THE FUTURE WE SUPPOSED TO DEAL 
// WITH UTF8 VALIDATION ON THE FLY AS DATA ARRIVE
// THAT MIGHT LOOK LIKE AN STRUCT INSTEAD 
// THAT PROGRESSES AS MORE 'UTF8' FRAME BYTES ARRIVE

#include <catch2/catch_test_macros.hpp>
#include <vector>
#include <string>

#include <wspp/wspp.h>

using wspp::detail::is_valid_utf8;

struct Utf8Case {
    std::vector<char> data;
    bool valid;
};

TEST_CASE("is_valid_utf8 accepts valid UTF-8 sequences (RFC 3629)") {
    const Utf8Case cases[] = {
        // ---- ASCII ----
        { { 'h','e','l','l','o' }, true },

        // ---- 2-byte ----
        { { char(0xC2), char(0xA2) }, true },               // ¢
        { { char(0xDF), char(0xBF) }, true },               // max 2-byte

        // ---- 3-byte ----
        { { char(0xE2), char(0x82), char(0xAC) }, true },   // €
        { { char(0xEF), char(0xBF), char(0xBF) }, true },   // max BMP

        // ---- 4-byte ----
        { { char(0xF0), char(0x9F), char(0x92), char(0xA9) }, true }, // 💩
        { { char(0xF4), char(0x8F), char(0xBF), char(0xBF) }, true }, // max Unicode

        // ---- mixed ----
        {
            {
                'A',
                char(0xC2), char(0xA2),
                char(0xE2), char(0x82), char(0xAC),
                char(0xF0), char(0x9F), char(0x92), char(0xA9)
            },
            true
        }
    };

    for (const auto& c : cases) {
        REQUIRE(is_valid_utf8(c.data) == c.valid);
    }
}

TEST_CASE("is_valid_utf8 rejects invalid UTF-8 sequences") {
    const Utf8Case cases[] = {
        // ---- overlong encodings ----
        { { char(0xC0), char(0xAF) }, false },               // '/' overlong
        { { char(0xE0), char(0x80), char(0x80) }, false },   // NUL overlong
        { { char(0xF0), char(0x80), char(0x80), char(0x80) }, false },

        // ---- invalid continuation ----
        { { char(0xC2), char(0x20) }, false },
        { { char(0xE2), char(0x28), char(0xA1) }, false },
        { { char(0xF0), char(0x28), char(0x8C), char(0xBC) }, false },

        // ---- truncated sequences ----
        { { char(0xC2) }, false },
        { { char(0xE2), char(0x82) }, false },
        { { char(0xF0), char(0x9F), char(0x92) }, false },

        // ---- surrogate halves ----
        { { char(0xED), char(0xA0), char(0x80) }, false },   // U+D800
        { { char(0xED), char(0xBF), char(0xBF) }, false },   // U+DFFF

        // ---- out of range (> U+10FFFF) ----
        { { char(0xF4), char(0x90), char(0x80), char(0x80) }, false },

        // ---- stray continuation ----
        { { char(0x80) }, false },
        { { char(0xBF) }, false },
    };

    for (const auto& c : cases) {
        REQUIRE(is_valid_utf8(c.data) == c.valid);
    }
}

TEST_CASE("is_valid_utf8 handles empty input") {
    std::vector<char> empty;
    REQUIRE(is_valid_utf8(empty));
}