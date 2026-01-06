#include <wspp/wspp.h>
#include <iostream>

int main() {
#ifndef WSPP_USE_OPENSSL
    std::cout << "Binance requires WSS (OpenSSL disabled)\n";
    return 0;
#else
    wspp::wss_client c;

    c.connect("wss://stream.binance.com:9443/ws/btcusdt@trade");

    c.on_message([&](wspp::message_view msg) {
        if (msg.is_text())
            std::cout << msg.text() << '\n';
        });

    c.on_close([](wspp::close_event e) {
        // e.reason: aborted, normal, remote
        std::cout << "client closed";
        if (e.code)
            std::cout << " with code " << int(*e.code);
        std::cout << '\n';
        });

    c.run();
#endif
}
