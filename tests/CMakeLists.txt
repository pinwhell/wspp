find_package(Catch2 REQUIRED)

add_executable(wspp_tests
    test_parse_ws_url.cpp
    test_base64.cpp 
    test_sha1.cpp 
    test_utf8_validation.cpp 
    test_validate_accept.cpp)

add_executable(autobahn_basic_echosv autobahn_basic_echosv.cpp)
target_link_libraries(autobahn_basic_echosv wspp::wspp)
add_executable(autobahn_basic_echoclient autobahn_basic_echoclient.cpp)
target_link_libraries(autobahn_basic_echoclient wspp::wspp)

target_link_libraries(wspp_tests PRIVATE
    wspp::wspp
    Catch2::Catch2WithMain
)

add_test(NAME wspp_tests COMMAND wspp_tests)