add_executable(ws_client_echo main.cpp)
target_link_libraries(ws_client_echo PRIVATE wspp::wspp)