cmake_minimum_required(VERSION 3.16)

include_directories(include)

project(wspp)

option(WSPP_USE_OPENSSL "Enable WSS (OpenSSL support)" ON)
option(WSPP_INSTALL "Enable installation rules" ON)
option(WSPP_BUILD_TESTS "Build wspp tests" OFF)
option(WSPP_BUILD_EXAMPLES "Build wspp examples" OFF)
option(WSPP_BUILD_PLAYGROUND "Build wspp playground (dev-only)" OFF)

if (PROJECT_IS_TOP_LEVEL)
    # Developer defaults
    set(WSPP_BUILD_TESTS ON CACHE BOOL "" FORCE)
    set(WSPP_BUILD_EXAMPLES ON CACHE BOOL "" FORCE)
    set(WSPP_BUILD_PLAYGROUND ON CACHE BOOL "" FORCE)
    set(WSPP_INSTALL ON CACHE BOOL "" FORCE)
endif()

if (NOT WSPP_INSTALL)
    set(CBUILDKIT_NOINSTALL ON)
endif()

include(cmake/CBuildKit.cmake)

add_library_ns(wspp wspp INTERFACE)
target_compile_features(wspp-wspp INTERFACE cxx_std_20)

target_include_dir_iface(
    wspp-wspp
    INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    include
)

if (WSPP_USE_OPENSSL)
    find_package(OpenSSL QUIET)

    if (OpenSSL_FOUND)
        target_compile_definitions(
            wspp-wspp
            INTERFACE
            WSPP_USE_OPENSSL
        )

        target_link_libraries(
            wspp-wspp
            INTERFACE
            OpenSSL::SSL
            OpenSSL::Crypto
        )
    else()
        message(STATUS "OpenSSL not found.. building wspp without WSS support")
    endif()

    set(WSPP_HAS_OPENSSL ${OpenSSLs_FOUND})
endif()

install_target_and_headers(
    wspp
    wspp
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include)

if (WSPP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if (WSPP_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if (WSPP_BUILD_PLAYGROUND)
    add_subdirectory(playground)
endif()

install_cfgpkg(wspp "include(CMakeFindDependencyMacro)

include(\"\${CMAKE_CURRENT_LIST_DIR}/wspp-wspp-targets.cmake\")

if (TARGET wspp::wspp)
    get_target_property(_wspp_libs wspp::wspp INTERFACE_LINK_LIBRARIES)
    if (_wspp_libs MATCHES \"OpenSSL::\")
        find_dependency(OpenSSL)
    endif()
endif()
")