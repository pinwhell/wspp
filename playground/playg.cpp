#include <wspp/wspp.h>

int main() {
    wspp::ws_client c;
    c.connect("ws://websockets.chilkat.io/wsChilkatEcho.ashx");
    //wspp::wss_client c;
    //c.connect("wss://echo.websocket.org/");
    //c.connect("wss://stream.binance.com:9443/ws/btcusdt@trade");

    c.on_text([&](std::string_view msg) {
        std::cout << msg << "\n";
        c.impl.send_close();
        });
    c.on_close([](wspp::ws_close_code code) {
        std::cout << "closed " << (std::uint16_t)code << "\n";
        });
    c.send("hello from socket"); // Will be echoed
    c.run();
}