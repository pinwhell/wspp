add_executable(ws_server_echo main.cpp)
target_link_libraries(ws_server_echo PRIVATE wspp::wspp)