# wspp

![C++20](https://img.shields.io/badge/cpp-20-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://img.shields.io/badge/build-passing-brightgreen)

> **Modern, header-only WebSocket library for C++20**  
> Build WebSocket clients & servers. Async, non-blocking, cross-platform, zero dependencies (optional OpenSSL for WSS).

---

**Why wspp?**  

- ✅ Header-only → drop-in, no linking hassle  
- ✅ Supports WS & WSS → secure and standard-compliant  
- ✅ Fully async/reactor → handle multiple connections efficiently  
- ✅ Cross-platform → Windows & Linux  
- ✅ Minimal and modern → C++20 clean API  

---

**Quick Client Example (1 minute to run):**  
```cpp
#include <wspp/wspp.h>
#include <iostream>

int main() {
    wspp::ws_client c;
    c.connect("ws://ws.vi-server.org/mirror");

    c.on_message([](wspp::message_view msg) {
        std::cout << "Received: " << msg.text() << "\n";
        c.close();
    });

    c.send("Hello wspp!");
    c.run();
}
```
```
Output:
Received: Hello wspp!
```

**Quick Server Example (1 minute to run):**  
```cpp
#include <wspp/wspp.h>
#include <iostream>

int main() {
    wspp::ws_server ws;
    ws.on_connection([](auto c) {
        c->on_message([c](wspp::message_view msg) {
            if (msg.is_text())
                std::cout << msg.text() << '\n';
            if (msg.is_binary())
                std::cout << "Size: " << msg.binary().size() << '\n';
            c->send(msg); // Echo
            });

        c->on_close([](wspp::ws_close_code code) {
            std::cout << "client closed " << int(code) << '\n';
            });
        });
    ws.listen(80);
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
