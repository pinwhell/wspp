add_executable(wss_client_echo main.cpp)
target_link_libraries(wss_client_echo PRIVATE wspp::wspp)
