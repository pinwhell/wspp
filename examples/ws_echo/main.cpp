#include <wspp/wspp.h>
#include <iostream>

int main() {
    wspp::ws_client c;

    c.connect("ws://ws.vi-server.org/mirror");

    c.on_text([&](std::string_view msg) {
        std::cout << msg << "\n";
        c.impl.send_close();
        });

    c.on_close([](wspp::ws_close_code code) {
        std::cout << "closed " << (uint16_t)code << "\n";
        });

    c.send("hello from ws_echo");
    c.run();
}