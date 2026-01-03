#include <wspp/wspp.h>

int main() {
    wspp::ws_server ws;
    ws.on_connection([](auto c) {
        c->on_message([c](wspp::message_view msg) {
            if (msg.is_text())
                std::cout << msg.text() << '\n';
            if (msg.is_binary())
                std::cout << "Size: " << msg.binary().size() << '\n';
            c->send(msg);
            });

        c->on_close([](wspp::ws_close_code code) {
            std::cout << "client closed " << int(code) << '\n';
            });
        });
    ws.listen(80);
    ws.run();
}