#include <wspp/wspp.h>
#include <iostream>
#include <format>

int main()
{
    wspp::ws_server sv;

    sv.on_connection([&sv](auto conn) {
        conn->on_message([&sv, conn](wspp::message_view msg) {
            if (!msg.is_text()) return;
            auto text = msg.text();

            if (text.starts_with("/sub ")) {
                auto room = text.substr(6);
                sv.subscribe(conn, room);
                return;
            }

            if (text.starts_with("/unsub ")) {
                auto room = text.substr(7);
                sv.unsubscribe(conn, room);
                return;
            }

            if (text.starts_with("/message ")) {
                auto space = text.find(' ', 9);
                auto room = text.substr(9, space - 9);
                auto msg = text.substr(space + 1);
                sv.publish(room, std::format("{}:{}: {}", room, conn->id(), msg));
                return;
            }
            });
        });

    sv.listen(8080);
    sv.run();
}