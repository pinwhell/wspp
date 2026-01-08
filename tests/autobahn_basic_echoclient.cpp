#include <wspp/wspp.h>
#include <iostream>
#include <format>

std::optional<int> get_case_count()
{
    wspp::ws_client w;
    std::optional<int> case_count;

    w.on_message([&](wspp::message_view msg) {
        case_count = std::stoi(std::string(msg.text()));
        w.close();
        });

    if (w.connect("ws://127.0.0.1:9001/getCaseCount") 
        != wspp::detail::ws_connect_result::ok)
        return {};

    w.run();

    return case_count;
}

void test_case(int case_i)
{
    wspp::ws_client c;

    c.on_message([&](wspp::message_view msg) {
        c.send(msg);
        });

    if (c.connect(std::format(
        "ws://127.0.0.1:9001/runCase?case={}&agent={}", case_i, "wspp"))
        != wspp::detail::ws_connect_result::ok) 
        return;

    c.run();
}

void flush_reports()
{
    wspp::ws_client c;

    if (c.connect(std::format(
        "ws://127.0.0.1:9001/updateReports?agent=wspp"))
        != wspp::detail::ws_connect_result::ok)
        return;

    c.on_open([&c] {
        c.close();
        });

    c.run();
}


int main() {
    if (auto case_count = get_case_count())
    {
        for (auto i = 0ull; i < *case_count; i++)
            test_case(i);
        flush_reports();
    }
}
