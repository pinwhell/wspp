#include <wspp/wspp.h>
#include <iostream>

int main() {
    wspp::ws_server server;

    server.on_connection([](auto conn) {
        conn->on_message([conn](wspp::message_view msg) {
            conn->send(msg);
            });

        conn->on_close([](auto ev) {
            //std::cout << "Closed: " << int(ev.code ? int(*ev.code) : int {}) << " " << int(ev.reason) << "\n";
            });
        });

    server.listen(9002);   // Autobahn default
    server.run();
}
