#include <wspp/wspp.h>
#include <iostream>

int main() {
#ifndef WSPP_USE_OPENSSL
    std::cout << "WSS not supported (OpenSSL disabled)\n";
    return 0;
#else
    wspp::wss_client c;

    c.connect("wss://echo.websocket.org/");

    c.on_text([&](std::string_view msg) {
        std::cout << msg << "\n";
        c.impl.send_close();
        });

    c.on_close([](wspp::ws_close_code code) {
        std::cout << "closed " << (uint16_t)code << "\n";
        });

    c.send("hello from wss_echo");
    c.run();
#endif
}
