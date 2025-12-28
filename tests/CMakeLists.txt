find_package(Catch2 REQUIRED)

add_executable(wspp_tests
    test_parse_ws_url.cpp
    test_base64.cpp 
    test_sha1.cpp 
    test_utf8_validation.cpp 
    test_validate_accept.cpp)

target_link_libraries(wspp_tests PRIVATE
    wspp::wspp
    Catch2::Catch2WithMain
)

add_test(NAME wspp_tests COMMAND wspp_tests)