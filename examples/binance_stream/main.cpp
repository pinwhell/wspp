#include <wspp/wspp.h>
#include <iostream>

int main() {
#ifndef WSPP_USE_OPENSSL
    std::cout << "Binance requires WSS (OpenSSL disabled)\n";
    return 0;
#else
    wspp::wss_client c;

    c.connect("wss://stream.binance.com:9443/ws/btcusdt@trade");

    c.on_text([](std::string_view msg) {
        std::cout << msg << "\n";
        });

    c.on_close([](wspp::ws_close_code code) {
        std::cout << "closed " << (uint16_t)code << "\n";
        });

    c.run();
#endif
}
