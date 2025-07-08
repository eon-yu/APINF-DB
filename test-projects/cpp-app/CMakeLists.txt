cmake_minimum_required(VERSION 3.10)
project(cpp-oss-test VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find packages
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

# Add executable
add_executable(cpp-oss-test 
    src/main.cpp
    src/network.cpp
    src/crypto.cpp
)

# Include directories
target_include_directories(cpp-oss-test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(cpp-oss-test
    ${OPENSSL_LIBRARIES}
    ${CURL_LIBRARIES}
    ${ZLIB_LIBRARIES}
    Threads::Threads
)

# Compiler flags
target_compile_options(cpp-oss-test PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

# Install
install(TARGETS cpp-oss-test
    DESTINATION bin
)

# CPack configuration
set(CPACK_PACKAGE_NAME "cpp-oss-test")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_DESCRIPTION "C++ OSS Compliance Test Application")
set(CPACK_PACKAGE_CONTACT "test@example.com")
include(CPack) 