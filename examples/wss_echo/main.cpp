#include <wspp/wspp.h>
#include <iostream>

int main() {
#ifndef WSPP_USE_OPENSSL
    std::cout << "WSS not supported (OpenSSL disabled)\n";
    return 0;
#else
    wspp::wss_client c;

    c.connect("wss://echo.websocket.org/");

    c.on_message([&](wspp::message_view msg) {
        if (msg.is_text())
            std::cout << msg.text() << '\n';

        if (msg.is_binary())
        {
            auto binary = msg.binary();
            std::cout << "Size: " << binary.size() << '\n';
            c.close();
        }
        });

    c.on_close([](wspp::ws_close_code code) {
        std::cout << "closed " << (uint16_t)code << "\n";
        });

    c.send("hello from wss_echo");
    c.send(std::vector<std::uint8_t>
    {/*Not so text*/ 0x00, 0x01, 0x02});
    c.run();
#endif
}
