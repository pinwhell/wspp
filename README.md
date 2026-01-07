# wspp

![C++20](https://img.shields.io/badge/cpp-20-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Autobahn](https://img.shields.io/badge/autobahn-passing-brightgreen)

> **Modern, header-only WebSocket library for C++20**  
> Build WebSocket clients & servers. Async, non-blocking, cross-platform, zero dependencies (optional OpenSSL for WSS).

---

**Why wspp?**  

- ✅ Header-only → drop-in, no linking hassle  
- ✅ Supports WS & WSS → secure
- ✅ RFC 6455 Compliant → Passing all Autobahn tests
- ✅ Fully async/reactor → handle multiple connections efficiently  
- ✅ Cross-platform → Windows & Linux  
- ✅ Minimal and modern → C++20 clean API  

---

**Quick Client Example (1 minute to run):**  
```cpp
#include <wspp/wspp.h>
#include <iostream>

int main() {
    wspp::wss_client c;
    // or wspp::ws_client for ws://
    c.connect("wss://echo.websocket.org/");

    c.on_message([](wspp::message_view msg) {
        std::cout << "Received: " << msg.text() << "\n";
        c.close();
    });

    c.on_close([](auto) {
        std::cout << "ws closed\n";
    });

    // or 
    // c.on_close([](wspp::close_event e) {
    //    // e.reason: aborted, normal, remote
    //    if (e.code)
    //        std::cout << "closed " << int(*e.code) << "\n";
    // });

    c.on_open([&c] {
        c.send("Hello wspp!");
    });
    
    c.run();
}
```
```
Output:
Received: Hello wspp!
ws closed
```

**Quick Server Example (1 minute to run):**  
```cpp
#include <wspp/wspp.h>
#include <iostream>

int main() {
    wspp::wss_server ws({ .cert = "server.crt", .key = "server.key" });
    // or wspp::ws_server for ws://
    ws.on_connection([](/*wspp::wss_server<>::connection_ptr or*/ auto c) {
        c->on_message([c](wspp::message_view msg) {
            if (msg.is_text())
                std::cout << msg.text() << '\n';
            if (msg.is_binary())
                std::cout << "Size: " << msg.binary().size() << '\n';
            c->send(msg); // Echo
            });

        c->on_close([](/*wspp::close_event or*/ auto e) {
            // e.reason: aborted, normal, remote
            std::cout << "client closed";
            if (e.code)
                std::cout << " with code " << int(*e.code);
            std::cout << '\n';
            });
        });
    ws.listen(80);
    ws.run();
}
```

**Mini Chat Server Example:**
```cpp
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
```

## Features

**wspp** is designed to make WebSockets in C++ effortless, modern, and reliable.  

- ⚡ **Header-only**  
  No linking, no build pain. Just include and go.  

- 🔒 **WS & WSS support**  
  Secure connections via OpenSSL (optional). Works out-of-the-box for public WebSocket endpoints.  

- ⏱ **Asynchronous / non-blocking**  
  Efficient, single-threaded event loop; supports multiple connections with minimal overhead.  

- 🌍 **Cross-platform**  
  Runs on Windows and Linux without platform-specific changes.  

- 🧩 **Flexible API**  
  - `ws_client` for plain WebSockets Client 
  - `ws_server` for plain WebSockets Server 
  - `wss_client` for secure WebSockets Client
  - `wss_server` for secure WebSockets Server 
  - Reactor pattern built-in for handling multiple streams  

- 🛡 **RFC-compliant**  
  Handles: fragmentation, masking, ping/pong, close codes, UTF-8 validation, handshake validation.  

- 💡 **Modern C++20 design**  
  Concepts, `std::string_view`, `std::chrono`, lambdas for callbacks, clean and minimal API.  

- 📦 **Drop-in examples**  
  Ready-to-run examples for Binance, echo servers, and more.  

- 🔧 **Developer-friendly**  
  Optional playground, tests, examples. Configure via CMake options:  
  - `WSPP_BUILD_TESTS`  
  - `WSPP_BUILD_EXAMPLES`  
  - `WSPP_BUILD_PLAYGROUND`


## Installation

**wspp** is CMake-friendly and header-only—getting started is effortless.

### Requirements
- C++20 compiler (GCC ≥10, Clang ≥11, MSVC ≥2019)
- CMake ≥3.16
- OpenSSL (optional, for `wss://` support)

### Using CMake

1. **Clone the repository**
```bash
git clone https://github.com/pinwhell/wspp.git
cd wspp
```
2. **Configure the project**
```bash
mkdir build && cd build
cmake .. -DWSPP_USE_OPENSSL=ON   # Enable WSS if you have OpenSSL
cmake --build .
```
3. **Install (optional)**
```bash
cmake --install .
```

This will install headers to `include/` and CMake targets to `lib/cmake/wspp`.
### Minimal Header-only Usage
```cpp
#include <wspp/wspp.h>
```
Just include and start coding—no linking, no setup.
### CMake Integration

Add to your project:
```cmake
find_package(wspp REQUIRED)
target_link_libraries(your_target PRIVATE wspp::wspp)
```

## License

`wspp` is released under the **MIT License**.  
