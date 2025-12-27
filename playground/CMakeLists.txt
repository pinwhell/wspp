add_executable(pg playg.cpp)
target_link_libraries(pg wspp::wspp)
target_compile_definitions(pg PRIVATE wspp::wspp)