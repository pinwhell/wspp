add_executable(binance_stream main.cpp)
target_link_libraries(binance_stream PRIVATE wspp::wspp)
