cmake_minimum_required(VERSION 3.10)

project(argon)

include(${CMAKE_BINARY_DIR}/conan_paths.cmake)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

find_package(OpenSSL)
find_package(libuv)
find_package(spdlog)

list(APPEND sources src/main.cc src/peer.cc)

add_executable(argon ${sources})
target_link_libraries(argon PUBLIC OpenSSL::OpenSSL)
target_link_libraries(argon PUBLIC libuv::libuv)
target_link_libraries(argon PUBLIC spdlog::spdlog)
target_compile_features(argon PRIVATE cxx_std_17)
target_compile_options(argon PUBLIC -Wall -Wextra -ggdb -O0)

