#include <wspp/wspp.h>
#include <iostream>
#include <format>

int main() {
    wspp::ws_server ws;
    // or wspp::wss_server for wss://
    ws.on_connection([&ws](auto c) {
        ws.broadcast_except(c, 
            std::format("{}:: joined.", c->id()));

        c->on_message([&ws, c](wspp::message_view msg) {
            if (!msg.is_text()) return;
            ws.broadcast_except(c, 
                std::format("{}: {}", 
                    c->id(), msg.text()));
            });

        c->on_close([c, &ws](wspp::close_event e) {
            ws.broadcast_except(c, std::format(
                "{}:: left.", c->id()));
            });
        });
    ws.listen(81);
    ws.run();
}
