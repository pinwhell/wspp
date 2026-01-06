#include <wspp/wspp.h>
#include <iostream>

int main() {
    wspp::wss_server ws({ .cert = "server.crt", .key = "server.key" });
    ws.on_connection([](auto c) {
        c->on_message([c](wspp::message_view msg) {
            if (msg.is_text())
                std::cout << msg.text() << '\n';
            if (msg.is_binary())
                std::cout << "Size: " << msg.binary().size() << '\n';
            c->send(msg);
            });

        c->on_close([](wspp::close_event e) {
            // e.reason, aborted, normal, remote
            std::cout << "client closed";
            if (e.code)
                std::cout << " with code " << int(*e.code);
            std::cout << '\n';
            });
        });
    ws.listen(4444);
    ws.run();
}